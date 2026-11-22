using System.Text.Json;
using AttackSurfaceMapper.Application.Abstractions;
using AttackSurfaceMapper.Application.Engine;
using AttackSurfaceMapper.Domain;
using AttackSurfaceMapper.Infrastructure.Network;

namespace AttackSurfaceMapper.Infrastructure.Modules;

/// <summary>
/// Ψάχνει στο αρχείο του Internet (Wayback Machine) παλιά URLs του στόχου: ξεχασμένα subdomains,
/// backups, αρχεία ρυθμίσεων, διαχειριστικά panels και endpoints.
/// </summary>
/// <remarks>
/// Ένα αρχείο που ήταν κάποτε δημόσιο (π.χ. <c>backup.sql</c>) μπορεί να υπάρχει ακόμα στον server,
/// ή να έχει αποθηκευτεί από το Wayback με όλα τα δεδομένα του.
/// </remarks>
/// <param name="http">Το factory των HTTP clients.</param>
public sealed class WaybackModule(IHttpClientFactory http) : IModule
{
    /// <summary>Πόσα URLs ζητάμε το πολύ από το Wayback.</summary>
    const int MaxUrls = 10000;
    /// <summary>Πόσα ευρήματα εκπέμπουμε το πολύ (τα πιο επικίνδυνα πρώτα).</summary>
    const int MaxFindings = 150;
    /// <summary>Πόσα νέα subdomains εκπέμπουμε το πολύ.</summary>
    const int MaxHosts = 300;

    /// <inheritdoc/>
    public string Name => "wayback";
    /// <inheritdoc/>
    public string Description => "Παλιά URLs από το Wayback Machine: ξεχασμένα subdomains, backups, αρχεία ρυθμίσεων, admin panels.";
    /// <inheritdoc/>
    public Footprint Level => Footprint.Passive;
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Watched { get; } = [EventTypes.Domain];
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Produced { get; } = [EventTypes.HistoricUrl, EventTypes.Host];

    /// <summary>
    /// Ζητά από το Wayback όλα τα URLs του domain και των subdomains του, και εκπέμπει τα
    /// ευαίσθητα (από τον υψηλότερο κίνδυνο) και τα subdomains που βρέθηκαν.
    /// </summary>
    /// <param name="e">Το domain-στόχος.</param>
    /// <param name="ctx">Το context του scan.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Ένα task που ολοκληρώνεται όταν εκπεμφθούν τα ευρήματα.</returns>
    public async Task HandleAsync(ScanEvent e, ScanContext ctx, CancellationToken ct)
    {
        var urls = await FetchAsync(e.Data, ctx, ct);
        if (urls is null) return;

        var hosts = urls.Select(u => Uri.TryCreate(u, UriKind.Absolute, out var x) ? Scope.NormalizeHost(x.Host) : null)
            .OfType<string>().Where(h => Scope.InScope(h, e.Data)).Distinct().Take(MaxHosts);
        foreach (var host in hosts) ctx.Emit(EventTypes.Host, host, e);

        var findings = urls.Select(HistoricUrls.Evaluate).OfType<HistoricUrlFinding>()
            .DistinctBy(f => f.Url)
            .OrderByDescending(f => Array.IndexOf(EventTypes.Risks, f.Risk))
            .Take(MaxFindings)
            .ToList();
        foreach (var f in findings) ctx.Emit(EventTypes.HistoricUrl, $"{f.Url} ({f.Reason})", e, f.Risk);

        ctx.Log($"Wayback: {urls.Count} URLs, {findings.Count} ενδιαφέροντα.");
    }

    /// <summary>
    /// Ζητά από το CDX API του Wayback τα μοναδικά URLs του domain (και των subdomains).
    /// </summary>
    /// <param name="domain">Το domain.</param>
    /// <param name="ctx">Το context του scan.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Τα URLs, ή <c>null</c> αν το Wayback δεν απάντησε.</returns>
    /// <remarks>Το Wayback είναι συχνά αργό (δεκάδες δευτερόλεπτα), γι' αυτό το όριο χρόνου είναι 90s.</remarks>
    async Task<List<string>?> FetchAsync(string domain, ScanContext ctx, CancellationToken ct)
    {
        var url = $"https://web.archive.org/cdx/search/cdx?url={Uri.EscapeDataString(domain)}&matchType=domain" +
                  $"&output=json&fl=original&collapse=urlkey&limit={MaxUrls}";
        // Το Wayback απορρίπτει συχνά ταυτόχρονα αιτήματα: μία επανάληψη μετά από λίγα δευτερόλεπτα.
        for (var attempt = 1; attempt <= 2; attempt++)
        {
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeout.CancelAfter(TimeSpan.FromSeconds(90));
                await using var stream = await http.CreateClient(HttpClients.External).GetStreamAsync(url, timeout.Token);
                using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: timeout.Token);
                // Η πρώτη γραμμή είναι η επικεφαλίδα (["original"]).
                return doc.RootElement.EnumerateArray().Skip(1)
                    .Select(row => row[0].GetString()).OfType<string>().ToList();
            }
            catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or JsonException && !ct.IsCancellationRequested)
            {
                if (attempt == 2)
                {
                    ctx.Log($"Το Wayback δεν απάντησε ({ex.GetType().Name}: {ex.Message}).", "warn");
                    return null;
                }
                await Task.Delay(TimeSpan.FromSeconds(5), ct);
            }
        }
        return null;
    }
}
