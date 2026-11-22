using System.Text;
using System.Text.RegularExpressions;
using AttackSurfaceMapper.Application.Abstractions;
using AttackSurfaceMapper.Application.Engine;
using AttackSurfaceMapper.Domain;
using AttackSurfaceMapper.Infrastructure.Network;

namespace AttackSurfaceMapper.Infrastructure.Modules;

/// <summary>
/// Περιηγείται στις σελίδες κάθε site (όπως ένας browser) και αναλύει το HTML και τα JavaScript
/// αρχεία: secrets, emails, cloud buckets, σελίδες σύνδεσης και συνδέσεις προς άλλα domains.
/// </summary>
/// <remarks>
/// Τα JavaScript αρχεία που σερβίρονται στον browser είναι από τα πιο συχνά σημεία διαρροής:
/// ό,τι υπάρχει εκεί (π.χ. ένα API key) το βλέπει οποιοσδήποτε επισκέπτης.
/// </remarks>
/// <param name="http">Το factory των HTTP clients.</param>
public sealed partial class WebSpiderModule(IHttpClientFactory http) : IModule
{
    /// <summary>Πόσες HTML σελίδες ανά site το πολύ.</summary>
    const int MaxPages = 15;
    /// <summary>Πόσα JavaScript αρχεία ανά site το πολύ.</summary>
    const int MaxScripts = 20;
    /// <summary>Πόσα bytes ανά αρχείο το πολύ (τα minified bundles μπορεί να είναι μεγάλα).</summary>
    const int MaxBytes = 2 * 1024 * 1024;
    /// <summary>Πόσα εξωτερικά hostnames ανά site το πολύ (για να μη "γεμίσει" ο γράφος με CDNs).</summary>
    const int MaxExternalHosts = 40;

    /// <inheritdoc/>
    public string Name => "web_spider";
    /// <inheritdoc/>
    public string Description => "Περιήγηση στις σελίδες και στα JavaScript αρχεία: secrets, emails, cloud buckets, σελίδες σύνδεσης.";
    /// <inheritdoc/>
    public Footprint Level => Footprint.Footprint;
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Watched { get; } = [EventTypes.Domain, EventTypes.Host];
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Produced { get; } =
        [EventTypes.JsFile, EventTypes.SecretInContent, EventTypes.Email, EventTypes.CloudBucket, EventTypes.LoginPage,
         EventTypes.Host, EventTypes.AffiliateHost];
    /// <inheritdoc/>
    /// <remarks>Ο spider κάνει πολλά αιτήματα ανά site, γι' αυτό το όριο είναι χαμηλότερο από των άλλων modules.</remarks>
    public int MaxTargets => 40;

    /// <summary>Βρίσκει links και scripts (href/src) στο HTML.</summary>
    [GeneratedRegex(@"(?:href|src)\s*=\s*[""']([^""'#\s]+)", RegexOptions.IgnoreCase)]
    private static partial Regex LinkRegex();

    /// <summary>Αναγνωρίζει πεδίο κωδικού (σελίδα σύνδεσης).</summary>
    [GeneratedRegex(@"<input[^>]+type\s*=\s*[""']?password", RegexOptions.IgnoreCase)]
    private static partial Regex PasswordInput();

    /// <summary>Καταλήξεις που δεν αξίζει να κατεβάσουμε (εικόνες, fonts, media, έγγραφα).</summary>
    static readonly HashSet<string> SkipExtensions =
        [".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".css", ".woff", ".woff2", ".ttf", ".eot",
         ".mp4", ".mp3", ".webm", ".pdf", ".zip", ".gz", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"];

    /// <summary>
    /// Περιηγείται στο site του host (σε πλάτος, ξεκινώντας από την αρχική σελίδα) και αναλύει
    /// κάθε σελίδα και κάθε JavaScript αρχείο του ίδιου host.
    /// </summary>
    /// <param name="e">Το hostname.</param>
    /// <param name="ctx">Το context του scan.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Ένα task που ολοκληρώνεται όταν τελειώσει η περιήγηση.</returns>
    public async Task HandleAsync(ScanEvent e, ScanContext ctx, CancellationToken ct)
    {
        var client = http.CreateClient(HttpClients.Target);
        var start = await FirstReachableAsync(client, e.Data, ct);
        if (start is null) return;

        var queue = new Queue<Uri>([start]);
        var seen = new HashSet<string> { start.AbsoluteUri };
        var scripts = new List<Uri>();
        var externalHosts = new HashSet<string>();
        var pages = 0;

        while (queue.Count > 0 && pages < MaxPages)
        {
            var url = queue.Dequeue();
            var html = await GetTextAsync(client, url, ct);
            if (html is null) continue;
            pages++;

            Analyze(html, url.AbsoluteUri, e, ctx);
            if (PasswordInput().IsMatch(html)) ctx.Emit(EventTypes.LoginPage, url.GetLeftPart(UriPartial.Path), e, "info");

            foreach (Match m in LinkRegex().Matches(html))
            {
                if (!Uri.TryCreate(url, System.Net.WebUtility.HtmlDecode(m.Groups[1].Value), out var link)) continue;
                if (link.Scheme is not ("http" or "https")) continue;
                link = new UriBuilder(link) { Fragment = "" }.Uri;

                if (!link.Host.Equals(url.Host, StringComparison.OrdinalIgnoreCase))
                {
                    if (externalHosts.Count < MaxExternalHosts && externalHosts.Add(link.Host.ToLowerInvariant()))
                        ctx.Emit(EventTypes.Host, link.Host, e);   // η μηχανή το κάνει AFFILIATE αν είναι εκτός scope
                    if (IsScript(link) && Scope.NormalizeHost(link.Host) is { } h && Scope.InScope(h, ctx.Target)) AddScript(link);
                    continue;
                }
                if (IsScript(link)) AddScript(link);
                else if (!SkipExtensions.Contains(Path.GetExtension(link.AbsolutePath).ToLowerInvariant()) && seen.Add(link.AbsoluteUri))
                    queue.Enqueue(link);
            }
        }

        foreach (var script in scripts.Take(MaxScripts))
        {
            ctx.Emit(EventTypes.JsFile, script.GetLeftPart(UriPartial.Path), e);
            if (await GetTextAsync(client, script, ct) is { } js) Analyze(js, script.GetLeftPart(UriPartial.Path), e, ctx);
        }
        ctx.Log($"{e.Data}: {pages} σελίδες, {Math.Min(scripts.Count, MaxScripts)} scripts");

        void AddScript(Uri u)
        {
            if (seen.Add(u.AbsoluteUri)) scripts.Add(u);
        }
    }

    /// <summary>
    /// Αναλύει ένα κείμενο (HTML ή JavaScript) και εκπέμπει secrets (με απόκρυψη), emails του
    /// στόχου και cloud buckets.
    /// </summary>
    /// <param name="text">Το κείμενο.</param>
    /// <param name="source">Από πού προήλθε (URL), για το μήνυμα.</param>
    /// <param name="e">Το hostname που εξετάζεται.</param>
    /// <param name="ctx">Το context του scan.</param>
    static void Analyze(string text, string source, ScanEvent e, ScanContext ctx)
    {
        foreach (var s in ContentPatterns.FindSecrets(text))
            ctx.Emit(EventTypes.SecretInContent, $"{s.Kind} {s.Masked} στο {source}", e, s.Risk);

        // Μόνο emails του στόχου: τα υπόλοιπα (βιβλιοθήκες, CDNs) είναι θόρυβος.
        foreach (var email in ContentPatterns.FindEmails(text))
            if (Scope.NormalizeHost(email[(email.IndexOf('@') + 1)..]) is { } domain && Scope.InScope(domain, ctx.Target))
                ctx.Emit(EventTypes.Email, email, e);

        foreach (var bucket in ContentPatterns.FindBuckets(text))
            ctx.Emit(EventTypes.CloudBucket, bucket, e);
    }

    /// <summary>Ελέγχει αν ένα URL είναι JavaScript αρχείο.</summary>
    /// <param name="u">Το URL.</param>
    /// <returns><c>true</c> για .js/.mjs.</returns>
    static bool IsScript(Uri u) => u.AbsolutePath.EndsWith(".js", StringComparison.OrdinalIgnoreCase)
                                   || u.AbsolutePath.EndsWith(".mjs", StringComparison.OrdinalIgnoreCase);

    /// <summary>Βρίσκει από πού απαντά το site: πρώτα HTTPS, μετά HTTP (ακολουθώντας ένα redirect).</summary>
    /// <param name="client">Ο HTTP client για τον στόχο.</param>
    /// <param name="host">Το hostname.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Το URL της αρχικής σελίδας, ή <c>null</c> αν δεν απαντά.</returns>
    static async Task<Uri?> FirstReachableAsync(HttpClient client, string host, CancellationToken ct)
    {
        foreach (var scheme in new[] { "https", "http" })
        {
            var url = new Uri($"{scheme}://{host}/");
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeout.CancelAfter(TimeSpan.FromSeconds(10));
                using var res = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
                if (res.Headers.Location is { } loc && (int)res.StatusCode is >= 300 and < 400)
                {
                    var next = loc.IsAbsoluteUri ? loc : new Uri(url, loc);
                    // Ακολουθούμε μόνο redirect στον ίδιο host (π.χ. http → https)· τα υπόλοιπα τα καταγράφει το http_fingerprint.
                    return next.Host.Equals(host, StringComparison.OrdinalIgnoreCase) ? next : null;
                }
                if (res.IsSuccessStatusCode) return url;
            }
            catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException && !ct.IsCancellationRequested)
            {
                // δοκιμάζουμε το επόμενο scheme
            }
        }
        return null;
    }

    /// <summary>
    /// Κατεβάζει ένα κείμενο (έως <see cref="MaxBytes"/>), μόνο αν είναι HTML ή JavaScript.
    /// </summary>
    /// <param name="client">Ο HTTP client.</param>
    /// <param name="url">Το URL.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Το κείμενο, ή <c>null</c> αν απέτυχε ή δεν είναι κείμενο.</returns>
    static async Task<string?> GetTextAsync(HttpClient client, Uri url, CancellationToken ct)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(15));
            using var res = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            if (!res.IsSuccessStatusCode) return null;
            var type = res.Content.Headers.ContentType?.MediaType ?? "";
            if (!type.Contains("html") && !type.Contains("javascript") && !type.Contains("text/plain")) return null;

            await using var stream = await res.Content.ReadAsStreamAsync(timeout.Token);
            var buffer = new byte[MaxBytes];
            int total = 0, read;
            while (total < MaxBytes && (read = await stream.ReadAsync(buffer.AsMemory(total, MaxBytes - total), timeout.Token)) > 0)
                total += read;
            return Encoding.UTF8.GetString(buffer, 0, total);
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException && !ct.IsCancellationRequested)
        {
            return null;
        }
    }
}
