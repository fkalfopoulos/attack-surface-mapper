using System.Net;
using System.Text.Json;
using AttackSurfaceMapper.Application.Abstractions;
using AttackSurfaceMapper.Application.Engine;
using AttackSurfaceMapper.Domain;
using AttackSurfaceMapper.Infrastructure.Network;
using Microsoft.Extensions.Logging;

namespace AttackSurfaceMapper.Infrastructure.Modules;

/// <summary>
/// Ελέγχει αν οι IP του στόχου βρίσκονται σε δημόσιες λίστες κακόβουλης δραστηριότητας
/// (Spamhaus DROP, abuse.ch Feodo Tracker).
/// </summary>
/// <remarks>
/// Οι λίστες κατεβαίνουν μία φορά και κρατιούνται στη μνήμη για 6 ώρες, κοινές για όλα τα scans·
/// κάθε έλεγχος γίνεται τοπικά, χωρίς να στέλνουμε τις IP του στόχου σε τρίτους.
/// </remarks>
/// <param name="http">Το factory των HTTP clients.</param>
/// <param name="logger">Ο logger.</param>
public sealed class BlocklistModule(IHttpClientFactory http, ILogger<BlocklistModule> logger) : IModule
{
    /// <summary>Πόσο συχνά ανανεώνονται οι λίστες.</summary>
    static readonly TimeSpan RefreshInterval = TimeSpan.FromHours(6);

    readonly SemaphoreSlim _refresh = new(1, 1);
    DateTime _loadedAt = DateTime.MinValue;
    List<IPNetwork> _spamhausDrop = [];
    HashSet<IPAddress> _feodo = [];

    /// <inheritdoc/>
    public string Name => "blocklists";
    /// <inheritdoc/>
    public string Description => "Έλεγχος IP σε λίστες κακόβουλης δραστηριότητας (Spamhaus DROP, abuse.ch Feodo Tracker).";
    /// <inheritdoc/>
    public Footprint Level => Footprint.Passive;
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Watched { get; } = [EventTypes.Ip];
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Produced { get; } = [EventTypes.Malicious];

    /// <summary>Ελέγχει μια IP σε όλες τις λίστες και εκπέμπει εύρημα για κάθε λίστα όπου βρίσκεται.</summary>
    /// <param name="e">Η IP.</param>
    /// <param name="ctx">Το context του scan.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Ένα task που ολοκληρώνεται όταν τελειώσει ο έλεγχος.</returns>
    public async Task HandleAsync(ScanEvent e, ScanContext ctx, CancellationToken ct)
    {
        if (!IPAddress.TryParse(e.Data, out var ip)) return;
        await EnsureLoadedAsync(ct);

        if (_spamhausDrop.FirstOrDefault(n => n.Contains(ip)) is { } net && net.PrefixLength > 0)
            ctx.Emit(EventTypes.Malicious, $"{ip}: Spamhaus DROP ({net}): δίκτυο ελεγχόμενο από κακόβουλους", e, "high");
        if (_feodo.Contains(ip))
            ctx.Emit(EventTypes.Malicious, $"{ip}: abuse.ch Feodo Tracker: botnet command & control server", e, "high");
    }

    /// <summary>
    /// Κατεβάζει τις λίστες αν δεν έχουν κατέβει ή αν είναι παλιότερες από <see cref="RefreshInterval"/>.
    /// Μόνο ένα scan τη φορά τις κατεβάζει· τα υπόλοιπα περιμένουν και χρησιμοποιούν το ίδιο αποτέλεσμα.
    /// </summary>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Ένα task που ολοκληρώνεται όταν οι λίστες είναι έτοιμες.</returns>
    async Task EnsureLoadedAsync(CancellationToken ct)
    {
        if (DateTime.UtcNow - _loadedAt < RefreshInterval) return;
        await _refresh.WaitAsync(ct);
        try
        {
            if (DateTime.UtcNow - _loadedAt < RefreshInterval) return;
            var client = http.CreateClient(HttpClients.External);
            _spamhausDrop = await LoadSpamhausAsync(client, ct) ?? _spamhausDrop;
            _feodo = await LoadFeodoAsync(client, ct) ?? _feodo;
            _loadedAt = DateTime.UtcNow;
            logger.LogInformation("Blocklists: {Drop} δίκτυα Spamhaus DROP, {Feodo} IP Feodo", _spamhausDrop.Count, _feodo.Count);
        }
        finally
        {
            _refresh.Release();
        }
    }

    /// <summary>Κατεβάζει τη λίστα Spamhaus DROP (ένα JSON object ανά γραμμή, με πεδίο "cidr").</summary>
    /// <param name="client">Ο HTTP client.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Τα δίκτυα, ή <c>null</c> αν απέτυχε η λήψη.</returns>
    async Task<List<IPNetwork>?> LoadSpamhausAsync(HttpClient client, CancellationToken ct)
    {
        try
        {
            var text = await client.GetStringAsync("https://www.spamhaus.org/drop/drop_v4.json", ct);
            var list = new List<IPNetwork>();
            foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                using var doc = JsonDocument.Parse(line);
                if (doc.RootElement.TryGetProperty("cidr", out var cidr) && IPNetwork.TryParse(cidr.GetString(), out var net))
                    list.Add(net);
            }
            return list;
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or TaskCanceledException && !ct.IsCancellationRequested)
        {
            logger.LogWarning("Αποτυχία λήψης Spamhaus DROP: {Error}", ex.Message);
            return null;
        }
    }

    /// <summary>Κατεβάζει τη λίστα IP του abuse.ch Feodo Tracker (μία IP ανά γραμμή, με σχόλια "#").</summary>
    /// <param name="client">Ο HTTP client.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Οι IP, ή <c>null</c> αν απέτυχε η λήψη.</returns>
    async Task<HashSet<IPAddress>?> LoadFeodoAsync(HttpClient client, CancellationToken ct)
    {
        try
        {
            var text = await client.GetStringAsync("https://feodotracker.abuse.ch/downloads/ipblocklist.txt", ct);
            return text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Where(l => !l.StartsWith('#'))
                .Select(l => IPAddress.TryParse(l, out var a) ? a : null)
                .OfType<IPAddress>()
                .ToHashSet();
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !ct.IsCancellationRequested)
        {
            logger.LogWarning("Αποτυχία λήψης Feodo Tracker: {Error}", ex.Message);
            return null;
        }
    }
}
