using System.Collections.Concurrent;
using System.Text.Json;
using AttackSurfaceMapper.Engine;

namespace AttackSurfaceMapper.Modules;

/// <summary>
/// Βρίσκει σε ποιο δίκτυο ανήκει κάθε IP: ASN, netblock, χώρα και πάροχος hosting/cloud (μέσω RIPEstat).
/// </summary>
public sealed class IpInfoModule : IModule
{
    /// <summary>
    /// Cache ανά IP, κοινή για όλα τα scans: πολλά hostnames μοιράζονται τις ίδιες IP (π.χ. CDN),
    /// και ένα δεύτερο scan του ίδιου στόχου δεν χρειάζεται να ξαναρωτήσει.
    /// </summary>
    readonly ConcurrentDictionary<string, Lazy<Task<IpInfo>>> _cache = new();

    /// <summary>Τα στοιχεία δικτύου μιας IP.</summary>
    /// <param name="Asn">Ο αριθμός AS, ή <c>null</c>.</param>
    /// <param name="Holder">Ο κάτοχος του AS (π.χ. "CLOUDFLARENET").</param>
    /// <param name="Prefix">Το prefix (π.χ. "104.16.0.0/13").</param>
    /// <param name="Country">Κωδικός χώρας (π.χ. "GR").</param>
    sealed record IpInfo(long? Asn, string? Holder, string? Prefix, string? Country);

    /// <inheritdoc/>
    public string Name => "ip_info";
    /// <inheritdoc/>
    public string Description => "ASN, netblock, χώρα και πάροχος hosting/cloud κάθε IP (RIPEstat).";
    /// <inheritdoc/>
    public Footprint Level => Footprint.Passive;
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Watched { get; } = [EventTypes.Ip, EventTypes.Ip6];
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Produced { get; } =
        [EventTypes.Asn, EventTypes.Netblock, EventTypes.Geo, EventTypes.Hosting];

    /// <summary>
    /// Βρίσκει τα στοιχεία δικτύου της IP και εκπέμπει ASN, netblock, χώρα και πάροχο.
    /// </summary>
    /// <param name="e">Η IP.</param>
    /// <param name="ctx">Το context του scan.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Ένα task που ολοκληρώνεται όταν εκπεμφθούν τα στοιχεία.</returns>
    public async Task HandleAsync(ScanEvent e, ScanContext ctx, CancellationToken ct)
    {
        var lazy = _cache.GetOrAdd(e.Data, ip => new Lazy<Task<IpInfo>>(() => LookupAsync(ip, ctx.External)));
        IpInfo info;
        try
        {
            info = await lazy.Value.WaitAsync(ct);
        }
        catch when (!ct.IsCancellationRequested)
        {
            _cache.TryRemove(e.Data, out _);   // να ξαναδοκιμάσει την επόμενη φορά
            throw;
        }

        if (info.Asn is { } asn) ctx.Emit(EventTypes.Asn, $"AS{asn} · {info.Holder}", e);
        if (info.Prefix is not null) ctx.Emit(EventTypes.Netblock, info.Prefix, e);
        if (info.Country is not null) ctx.Emit(EventTypes.Geo, info.Country, e);
        if (DetectProvider(info.Holder) is { } provider) ctx.Emit(EventTypes.Hosting, provider, e);
    }

    /// <summary>
    /// Ρωτά το RIPEstat για το prefix, το ASN και τη χώρα μιας IP.
    /// </summary>
    /// <param name="ip">Η IP.</param>
    /// <param name="http">HTTP client για APIs τρίτων.</param>
    /// <returns>Τα στοιχεία δικτύου (με <c>null</c> σε ό,τι δεν βρέθηκε).</returns>
    /// <remarks>
    /// Δεν δέχεται token ακύρωσης: το αποτέλεσμα μπαίνει σε κοινή cache, και δεν θέλουμε η ακύρωση
    /// ενός scan να αφήσει "χαλασμένη" εγγραφή για τα υπόλοιπα.
    /// </remarks>
    static async Task<IpInfo> LookupAsync(string ip, HttpClient http)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var q = Uri.EscapeDataString(ip);

        long? asn = null;
        string? holder = null, prefix = null, country = null;

        using (var doc = await GetJsonAsync(http, $"https://stat.ripe.net/data/prefix-overview/data.json?resource={q}&sourceapp=attack-surface-mapper", timeout.Token))
        {
            var data = doc.RootElement.GetProperty("data");
            if (data.TryGetProperty("resource", out var r) && data.GetProperty("announced").GetBoolean()) prefix = r.GetString();
            if (data.TryGetProperty("asns", out var asns) && asns.GetArrayLength() > 0)
            {
                asn = asns[0].GetProperty("asn").GetInt64();
                holder = asns[0].GetProperty("holder").GetString();
            }
        }

        using (var doc = await GetJsonAsync(http, $"https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource={q}&sourceapp=attack-surface-mapper", timeout.Token))
        {
            var located = doc.RootElement.GetProperty("data").GetProperty("located_resources");
            if (located.GetArrayLength() > 0 && located[0].GetProperty("locations") is { ValueKind: JsonValueKind.Array } locs
                && locs.GetArrayLength() > 0 && locs[0].TryGetProperty("country", out var c))
                country = c.GetString();
        }

        return new IpInfo(asn, holder, prefix, string.IsNullOrEmpty(country) || country == "?" ? null : country);
    }

    /// <summary>Κάνει GET σε ένα URL και επιστρέφει το JSON της απάντησης.</summary>
    /// <param name="http">Ο HTTP client.</param>
    /// <param name="url">Το URL.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Το JSON. Ο caller το κάνει dispose.</returns>
    static async Task<JsonDocument> GetJsonAsync(HttpClient http, string url, CancellationToken ct)
    {
        await using var s = await http.GetStreamAsync(url, ct);
        return await JsonDocument.ParseAsync(s, cancellationToken: ct);
    }

    /// <summary>
    /// Αναγνωρίζει γνωστούς παρόχους hosting/cloud από το όνομα του κατόχου του AS.
    /// </summary>
    /// <param name="holder">Ο κάτοχος του AS, π.χ. "AMAZON-02 - Amazon.com, Inc.".</param>
    /// <returns>Το όνομα του παρόχου, ή <c>null</c> αν δεν είναι γνωστός.</returns>
    static string? DetectProvider(string? holder)
    {
        if (holder is null) return null;
        foreach (var (needle, name) in Providers)
            if (holder.Contains(needle, StringComparison.OrdinalIgnoreCase)) return name;
        return null;
    }

    /// <summary>Λέξεις-κλειδιά στον κάτοχο του AS και ο πάροχος που αντιστοιχούν.</summary>
    static readonly (string Needle, string Name)[] Providers =
    [
        ("AMAZON", "Amazon Web Services"), ("MICROSOFT", "Microsoft Azure"), ("GOOGLE", "Google Cloud"),
        ("CLOUDFLARE", "Cloudflare"), ("AKAMAI", "Akamai"), ("FASTLY", "Fastly"), ("DIGITALOCEAN", "DigitalOcean"),
        ("HETZNER", "Hetzner"), ("OVH", "OVHcloud"), ("LINODE", "Akamai (Linode)"), ("ORACLE", "Oracle Cloud"),
        ("ALIBABA", "Alibaba Cloud"), ("VULTR", "Vultr"), ("CHOOPA", "Vultr"), ("GITHUB", "GitHub"),
        ("NETLIFY", "Netlify"), ("VERCEL", "Vercel"), ("HEROKU", "Heroku"), ("SCALEWAY", "Scaleway"),
        ("CONTABO", "Contabo"), ("IONOS", "IONOS"), ("1&1", "IONOS"), ("GODADDY", "GoDaddy"),
    ];
}
