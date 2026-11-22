using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using AttackSurfaceMapper.Application.Abstractions;
using AttackSurfaceMapper.Application.Engine;
using AttackSurfaceMapper.Domain;
using AttackSurfaceMapper.Infrastructure.Network;

namespace AttackSurfaceMapper.Infrastructure.Modules;

/// <summary>
/// Επισκέπτεται την αρχική σελίδα κάθε host (όπως ένας browser) και καταγράφει web server,
/// τεχνολογίες, security headers που λείπουν και redirects προς άλλα domains.
/// </summary>
/// <param name="http">Το factory των HTTP clients.</param>
public sealed partial class HttpFingerprintModule(IHttpClientFactory http) : IModule
{
    /// <summary>Πόσα bytes της σελίδας διαβάζουμε το πολύ (αρκούν για την ανίχνευση τεχνολογιών).</summary>
    const int MaxBody = 512 * 1024;

    /// <summary>Πόσα redirects ακολουθούμε το πολύ.</summary>
    const int MaxRedirects = 5;

    /// <inheritdoc/>
    public string Name => "http_fingerprint";
    /// <inheritdoc/>
    public string Description => "Web server, τεχνολογίες (CMS, framework, CDN), security headers και redirects κάθε site.";
    /// <inheritdoc/>
    public Footprint Level => Footprint.Footprint;
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Watched { get; } = [EventTypes.Domain, EventTypes.Host];
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Produced { get; } =
        [EventTypes.Url, EventTypes.NoTls, EventTypes.WebServer, EventTypes.WebTech, EventTypes.MissingHeaders,
         EventTypes.Host, EventTypes.AffiliateHost];

    /// <summary>Η τελική απάντηση μιας σελίδας μετά τα redirects.</summary>
    /// <param name="Url">Το τελικό URL.</param>
    /// <param name="Status">Ο HTTP κωδικός.</param>
    /// <param name="Headers">Όλα τα headers (απάντησης και περιεχομένου), χωρίς διάκριση πεζών/κεφαλαίων.</param>
    /// <param name="Cookies">Τα ονόματα των cookies.</param>
    /// <param name="Body">Η αρχή του HTML.</param>
    sealed record Page(Uri Url, int Status, Dictionary<string, string> Headers, List<string> Cookies, string Body);

    /// <summary>
    /// Δοκιμάζει πρώτα HTTPS και μετά HTTP, και αναλύει την πρώτη σελίδα που απαντά.
    /// </summary>
    /// <param name="e">Το hostname.</param>
    /// <param name="ctx">Το context του scan.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Ένα task που ολοκληρώνεται όταν τελειώσει η ανάλυση.</returns>
    public async Task HandleAsync(ScanEvent e, ScanContext ctx, CancellationToken ct)
    {
        var page = await FetchAsync(new Uri($"https://{e.Data}/"), e, ctx, ct);
        if (page is null)
        {
            page = await FetchAsync(new Uri($"http://{e.Data}/"), e, ctx, ct);
            if (page is null) return;
            if (page.Url.Scheme == Uri.UriSchemeHttp)
                ctx.Emit(EventTypes.NoTls, $"http://{e.Data}/", e, "medium");
        }

        var title = TitleRegex().Match(page.Body) is { Success: true } m
            ? WebUtility.HtmlDecode(m.Groups[1].Value).Trim()
            : null;
        ctx.Emit(EventTypes.Url, $"{page.Url} [{page.Status}]" + (string.IsNullOrEmpty(title) ? "" : $" «{Truncate(title, 80)}»"), e);

        if (page.Headers.TryGetValue("server", out var server))
            ctx.Emit(EventTypes.WebServer, server, e, HasVersion(server) ? "low" : null);
        if (page.Headers.TryGetValue("x-powered-by", out var powered))
            ctx.Emit(EventTypes.WebTech, powered, e, HasVersion(powered) ? "low" : null);

        foreach (var tech in DetectTechnologies(page)) ctx.Emit(EventTypes.WebTech, tech, e);

        var missing = MissingSecurityHeaders(page);
        if (missing.Count > 0) ctx.Emit(EventTypes.MissingHeaders, "Λείπουν: " + string.Join(", ", missing), e, "low");
    }

    /// <summary>
    /// Κατεβάζει μια σελίδα ακολουθώντας μέχρι <see cref="MaxRedirects"/> redirects. Αν ένα redirect
    /// οδηγεί εκτός scope, καταγράφει το νέο hostname και σταματά εκεί.
    /// </summary>
    /// <param name="url">Το αρχικό URL.</param>
    /// <param name="e">Το hostname που εξετάζεται.</param>
    /// <param name="ctx">Το context του scan.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Η τελική σελίδα, ή <c>null</c> αν δεν απάντησε.</returns>
    async Task<Page?> FetchAsync(Uri url, ScanEvent e, ScanContext ctx, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));
        try
        {
            for (var i = 0; i <= MaxRedirects; i++)
            {
                using var res = await http.CreateClient(HttpClients.Target).GetAsync(url, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
                var status = (int)res.StatusCode;

                if (status is >= 300 and < 400 && res.Headers.Location is { } location)
                {
                    var next = location.IsAbsoluteUri ? location : new Uri(url, location);
                    if (next.Scheme is not ("http" or "https")) return null;
                    if (!next.Host.Equals(url.Host, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.Emit(EventTypes.Host, next.Host, e);
                        if (!Scope.InScope(next.Host.ToLowerInvariant(), ctx.Target)) return await ReadAsync(url, res, timeout.Token);
                    }
                    url = next;
                    continue;
                }
                return await ReadAsync(url, res, timeout.Token);
            }
            return null;
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException && !ct.IsCancellationRequested)
        {
            return null;
        }
    }

    /// <summary>Διαβάζει headers, cookies και τα πρώτα <see cref="MaxBody"/> bytes μιας απάντησης.</summary>
    /// <param name="url">Το URL της απάντησης.</param>
    /// <param name="res">Η απάντηση.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Η σελίδα.</returns>
    async Task<Page> ReadAsync(Uri url, HttpResponseMessage res, CancellationToken ct)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (k, v) in res.Headers.Concat(res.Content.Headers)) headers[k] = string.Join(", ", v);

        var cookies = res.Headers.TryGetValues("Set-Cookie", out var sc)
            ? sc.Select(c => c.Split('=', 2)[0].Trim()).ToList()
            : [];

        await using var stream = await res.Content.ReadAsStreamAsync(ct);
        var buffer = new byte[MaxBody];
        var total = 0;
        int read;
        while (total < MaxBody && (read = await stream.ReadAsync(buffer.AsMemory(total, MaxBody - total), ct)) > 0) total += read;

        return new Page(url, (int)res.StatusCode, headers, cookies, Encoding.UTF8.GetString(buffer, 0, total));
    }

    /// <summary>
    /// Αναγνωρίζει τεχνολογίες από headers, cookies, το meta "generator" και υπογραφές στο HTML.
    /// </summary>
    /// <param name="page">Η σελίδα.</param>
    /// <returns>Τα ονόματα των τεχνολογιών που βρέθηκαν.</returns>
    static IEnumerable<string> DetectTechnologies(Page page)
    {
        var found = new HashSet<string>();
        foreach (var (header, name) in HeaderSignatures)
            if (page.Headers.ContainsKey(header)) found.Add(name);
        foreach (var (cookie, name) in CookieSignatures)
            if (page.Cookies.Any(c => c.StartsWith(cookie, StringComparison.OrdinalIgnoreCase))) found.Add(name);
        foreach (var (marker, name) in BodySignatures)
            if (page.Body.Contains(marker, StringComparison.Ordinal)) found.Add(name);
        if (GeneratorRegex().Match(page.Body) is { Success: true } g) found.Add(WebUtility.HtmlDecode(g.Groups[1].Value).Trim());
        return found;
    }

    /// <summary>
    /// Επιστρέφει τα σημαντικά security headers που λείπουν από μια σελίδα HTTPS.
    /// </summary>
    /// <param name="page">Η σελίδα.</param>
    /// <returns>Τα ονόματα των headers που λείπουν (κενή λίστα για HTTP ή σελίδες σφάλματος).</returns>
    static List<string> MissingSecurityHeaders(Page page)
    {
        var missing = new List<string>();
        if (page.Url.Scheme != Uri.UriSchemeHttps || page.Status >= 400) return missing;
        var h = page.Headers;
        if (!h.ContainsKey("strict-transport-security")) missing.Add("HSTS");
        var csp = h.GetValueOrDefault("content-security-policy");
        if (csp is null) missing.Add("CSP");
        if (!h.ContainsKey("x-content-type-options")) missing.Add("X-Content-Type-Options");
        if (!h.ContainsKey("x-frame-options") && (csp is null || !csp.Contains("frame-ancestors"))) missing.Add("X-Frame-Options");
        return missing;
    }

    /// <summary>Ελέγχει αν ένα banner αποκαλύπτει έκδοση (π.χ. "nginx/1.18.0"), που διευκολύνει την εύρεση γνωστών ευπαθειών.</summary>
    /// <param name="banner">Το banner.</param>
    /// <returns><c>true</c> αν περιέχει αριθμό έκδοσης.</returns>
    static bool HasVersion(string banner) => VersionRegex().IsMatch(banner);

    /// <summary>Κόβει ένα κείμενο στο μέγιστο μήκος, προσθέτοντας "…".</summary>
    /// <param name="s">Το κείμενο.</param>
    /// <param name="max">Το μέγιστο μήκος.</param>
    /// <returns>Το κομμένο κείμενο.</returns>
    static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "…";

    /// <summary>Βρίσκει τον τίτλο της σελίδας.</summary>
    [GeneratedRegex(@"<title[^>]*>([^<]{1,300})</title>", RegexOptions.IgnoreCase)]
    private static partial Regex TitleRegex();

    /// <summary>Βρίσκει το <c>&lt;meta name="generator"&gt;</c> (π.χ. "WordPress 6.4").</summary>
    [GeneratedRegex(@"<meta[^>]+name=[""']generator[""'][^>]+content=[""']([^""']{1,100})", RegexOptions.IgnoreCase)]
    private static partial Regex GeneratorRegex();

    /// <summary>Βρίσκει αριθμό έκδοσης μέσα σε banner.</summary>
    [GeneratedRegex(@"\d+\.\d+")]
    private static partial Regex VersionRegex();

    /// <summary>Headers που αποκαλύπτουν CDN ή πλατφόρμα.</summary>
    static readonly (string Header, string Name)[] HeaderSignatures =
    [
        ("cf-ray", "Cloudflare"), ("x-amz-cf-id", "Amazon CloudFront"), ("x-vercel-id", "Vercel"),
        ("x-nf-request-id", "Netlify"), ("x-github-request-id", "GitHub Pages"), ("x-azure-ref", "Azure Front Door"),
        ("x-fastly-request-id", "Fastly"), ("x-akamai-transformed", "Akamai"), ("x-drupal-cache", "Drupal"),
        ("x-shopify-stage", "Shopify"), ("x-wix-request-id", "Wix"), ("x-aspnet-version", "ASP.NET"),
        ("x-litespeed-cache", "LiteSpeed"), ("x-varnish", "Varnish"),
    ];

    /// <summary>Cookies που αποκαλύπτουν τη γλώσσα ή το framework του backend.</summary>
    static readonly (string Cookie, string Name)[] CookieSignatures =
    [
        ("PHPSESSID", "PHP"), ("ASP.NET_SessionId", "ASP.NET"), (".AspNetCore.", "ASP.NET Core"),
        ("JSESSIONID", "Java"), ("laravel_session", "Laravel"), ("ci_session", "CodeIgniter"),
        ("wordpress_", "WordPress"), ("wp-settings", "WordPress"), ("_shopify", "Shopify"),
        ("connect.sid", "Node.js (Express)"), ("AWSALB", "AWS Load Balancer"),
    ];

    /// <summary>Υπογραφές στο HTML για CMS και frontend frameworks.</summary>
    static readonly (string Marker, string Name)[] BodySignatures =
    [
        ("/wp-content/", "WordPress"), ("/wp-includes/", "WordPress"), ("Drupal.settings", "Drupal"),
        ("/media/jui/", "Joomla"), ("__NEXT_DATA__", "Next.js"), ("__NUXT__", "Nuxt"), ("___gatsby", "Gatsby"),
        ("ng-version=", "Angular"), ("data-reactroot", "React"), ("cdn.shopify.com", "Shopify"),
        ("static.wixstatic.com", "Wix"), ("squarespace.com", "Squarespace"), ("_framework/blazor", "Blazor"),
        ("googletagmanager.com", "Google Tag Manager"), ("google-analytics.com", "Google Analytics"),
        ("hotjar.com", "Hotjar"), ("js.stripe.com", "Stripe"), ("recaptcha", "Google reCAPTCHA"),
    ];
}
