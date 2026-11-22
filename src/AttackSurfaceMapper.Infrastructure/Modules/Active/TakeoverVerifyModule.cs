using System.Text;
using AttackSurfaceMapper.Application.Abstractions;
using AttackSurfaceMapper.Application.Engine;
using AttackSurfaceMapper.Domain;
using AttackSurfaceMapper.Infrastructure.Network;
using DnsClient;

namespace AttackSurfaceMapper.Infrastructure.Modules.Active;

/// <summary>
/// ACTIVE: για κάθε subdomain με CNAME προς υπηρεσία τρίτου (GitHub Pages, S3, Heroku…), επισκέπτεται
/// τη σελίδα και ελέγχει αν η υπηρεσία λέει ότι ο πόρος δεν υπάρχει, δηλαδή ότι το subdomain μπορεί
/// να καταληφθεί από οποιονδήποτε.
/// </summary>
/// <remarks>
/// Συμπληρώνει τον παθητικό έλεγχο του <c>dns_resolve</c> (που βλέπει μόνο NXDOMAIN): πολλές
/// υπηρεσίες απαντούν κανονικά στο DNS, αλλά σερβίρουν σελίδα "δεν υπάρχει" που μπορεί να διεκδικηθεί.
/// Δεν επιχειρεί ποτέ το ίδιο το takeover.
/// </remarks>
/// <param name="dns">Ο DNS client.</param>
/// <param name="http">Το factory των HTTP clients.</param>
public sealed class TakeoverVerifyModule(ILookupClient dns, IHttpClientFactory http) : IModule
{
    /// <summary>Πόσα bytes της σελίδας διαβάζουμε (το μήνυμα της υπηρεσίας είναι στην αρχή).</summary>
    const int MaxBytes = 128 * 1024;

    /// <inheritdoc/>
    public string Name => "takeover_verify";
    /// <inheritdoc/>
    public string Description => "Επιβεβαίωση subdomain takeover με τα fingerprints κάθε υπηρεσίας (GitHub Pages, S3, Heroku, Azure…).";
    /// <inheritdoc/>
    public Footprint Level => Footprint.Active;
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Watched { get; } = [EventTypes.Host];
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Produced { get; } = [EventTypes.Takeover];
    /// <inheritdoc/>
    public int MaxTargets => 300;

    /// <summary>
    /// Αν ο host έχει CNAME προς γνωστή υπηρεσία, κατεβάζει τη σελίδα του και ελέγχει το fingerprint.
    /// </summary>
    /// <param name="e">Το hostname.</param>
    /// <param name="ctx">Το context του scan.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Ένα task που ολοκληρώνεται όταν τελειώσει ο έλεγχος.</returns>
    public async Task HandleAsync(ScanEvent e, ScanContext ctx, CancellationToken ct)
    {
        var res = await dns.QueryAsync(e.Data, QueryType.CNAME, cancellationToken: ct);
        var cname = res.Answers.CnameRecords().Select(r => r.CanonicalName.Value.TrimEnd('.')).FirstOrDefault();
        if (cname is null || TakeoverFingerprints.ForCname(cname) is not { } fingerprint) return;

        foreach (var scheme in new[] { "https", "http" })
        {
            var body = await GetBodyAsync(new Uri($"{scheme}://{e.Data}/"), ct);
            if (body is null) continue;
            if (TakeoverFingerprints.Matches(fingerprint, body))
                ctx.Emit(EventTypes.Takeover, $"{e.Data} → {cname} ({fingerprint.Service}): επιβεβαιωμένο από το περιεχόμενο", e, "high");
            return;   // η υπηρεσία απάντησε· δεν χρειάζεται δεύτερο scheme
        }
    }

    /// <summary>Κατεβάζει την αρχή μιας σελίδας (μόνο από δημόσιες IP), ανεξάρτητα από τον κωδικό HTTP.</summary>
    /// <param name="url">Το URL.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Το κείμενο, ή <c>null</c> αν δεν απάντησε.</returns>
    async Task<string?> GetBodyAsync(Uri url, CancellationToken ct)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(10));
            using var resp = await http.CreateClient(HttpClients.Target).GetAsync(url, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            await using var stream = await resp.Content.ReadAsStreamAsync(timeout.Token);
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
