using System.Text.Json;
using AttackSurfaceMapper.Engine;

namespace AttackSurfaceMapper.Modules;

/// <summary>
/// Βρίσκει subdomains από τα δημόσια logs Certificate Transparency (crt.sh, με εφεδρεία το Cert Spotter).
/// </summary>
/// <remarks>
/// Κάθε SSL certificate που εκδίδεται από δημόσια CA καταγράφεται σε δημόσια logs. Έτσι τα
/// hostnames του certificate γίνονται δημόσια, ακόμα και για εσωτερικά ή "κρυφά" subdomains.
/// Είναι η καλύτερη παθητική πηγή subdomains.
/// </remarks>
public sealed class CertTransparencyModule : IModule
{
    /// <summary>Μέγιστο πλήθος subdomains που κρατάμε από αυτή την πηγή.</summary>
    const int MaxNames = 1000;

    /// <inheritdoc/>
    public string Name => "cert_transparency";
    /// <inheritdoc/>
    public string Description => "Subdomains από τα δημόσια logs Certificate Transparency (crt.sh, Cert Spotter).";
    /// <inheritdoc/>
    public Footprint Level => Footprint.Passive;
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Watched { get; } = [EventTypes.Domain];
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Produced { get; } = [EventTypes.Host];

    /// <summary>
    /// Ζητά από το crt.sh (ή, αν αποτύχει, από το Cert Spotter) όλα τα certificates του domain και
    /// εκπέμπει τα hostnames τους που ανήκουν στον στόχο.
    /// </summary>
    /// <param name="e">Το domain-στόχος.</param>
    /// <param name="ctx">Το context του scan.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Ένα task που ολοκληρώνεται όταν εκπεμφθούν όλα τα subdomains.</returns>
    public async Task HandleAsync(ScanEvent e, ScanContext ctx, CancellationToken ct)
    {
        HashSet<string> names;
        try
        {
            names = await FromCrtShAsync(e.Data, ctx, ct);
            ctx.Log($"crt.sh: {names.Count} ονόματα");
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException && !ct.IsCancellationRequested)
        {
            ctx.Log($"Το crt.sh απέτυχε ({ex.Message}). Δοκιμή με Cert Spotter.", "warn");
            names = await FromCertSpotterAsync(e.Data, ctx, ct);
            ctx.Log($"Cert Spotter: {names.Count} ονόματα");
        }

        foreach (var name in names
                     .Select(Scope.NormalizeHost)
                     .OfType<string>()
                     .Where(n => Scope.InScope(n, e.Data))
                     .Distinct()
                     .Take(MaxNames))
            ctx.Emit(EventTypes.Host, name, e);
    }

    /// <summary>Διαβάζει τα hostnames όλων των certificates του domain από το crt.sh.</summary>
    /// <param name="domain">Το domain.</param>
    /// <param name="ctx">Το context του scan.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Τα hostnames (ακατέργαστα, μπορεί να περιέχουν wildcards).</returns>
    static async Task<HashSet<string>> FromCrtShAsync(string domain, ScanContext ctx, CancellationToken ct)
    {
        var url = $"https://crt.sh/?q={Uri.EscapeDataString("%." + domain)}&output=json&exclude=expired";
        await using var stream = await ctx.External.GetStreamAsync(url, ct);
        using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);

        var names = new HashSet<string>();
        foreach (var cert in doc.RootElement.EnumerateArray())
        {
            if (cert.TryGetProperty("common_name", out var cn) && cn.GetString() is { } c) names.Add(c);
            if (cert.TryGetProperty("name_value", out var nv) && nv.GetString() is { } v)
                foreach (var n in v.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    names.Add(n);
        }
        return names;
    }

    /// <summary>Διαβάζει τα hostnames των certificates από το Cert Spotter (εφεδρική πηγή, πρώτη σελίδα).</summary>
    /// <param name="domain">Το domain.</param>
    /// <param name="ctx">Το context του scan.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Τα hostnames.</returns>
    static async Task<HashSet<string>> FromCertSpotterAsync(string domain, ScanContext ctx, CancellationToken ct)
    {
        var url = $"https://api.certspotter.com/v1/issuances?domain={Uri.EscapeDataString(domain)}&include_subdomains=true&expand=dns_names";
        await using var stream = await ctx.External.GetStreamAsync(url, ct);
        using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);

        var names = new HashSet<string>();
        foreach (var issuance in doc.RootElement.EnumerateArray())
            if (issuance.TryGetProperty("dns_names", out var dns))
                foreach (var n in dns.EnumerateArray())
                    if (n.GetString() is { } s) names.Add(s);
        return names;
    }
}
