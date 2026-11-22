using System.Net;
using AttackSurfaceMapper.Application.Abstractions;
using AttackSurfaceMapper.Application.Engine;
using AttackSurfaceMapper.Domain;
using AttackSurfaceMapper.Infrastructure.Network;
using DnsClient;
using DnsClient.Protocol;

namespace AttackSurfaceMapper.Infrastructure.Modules.Active;

/// <summary>
/// ACTIVE: ζητά από κάθε nameserver του domain ολόκληρη τη ζώνη DNS (AXFR). Αν κάποιος τη δώσει,
/// είναι σοβαρή λάθος ρύθμιση: αποκαλύπτει όλα τα hostnames, και τα εσωτερικά.
/// </summary>
/// <param name="dns">Ο DNS client (για τα NS records).</param>
public sealed class ZoneTransferModule(ILookupClient dns) : IModule
{
    /// <summary>Πόσα hostnames από τη ζώνη εκπέμπουμε το πολύ.</summary>
    const int MaxHosts = 500;

    /// <inheritdoc/>
    public string Name => "zone_transfer";
    /// <inheritdoc/>
    public string Description => "Έλεγχος αν οι nameservers δίνουν σε οποιονδήποτε ολόκληρη τη ζώνη DNS (AXFR).";
    /// <inheritdoc/>
    public Footprint Level => Footprint.Active;
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Watched { get; } = [EventTypes.Domain];
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Produced { get; } = [EventTypes.DnsIssue, EventTypes.Host];

    /// <summary>
    /// Δοκιμάζει AXFR σε κάθε nameserver του domain. Για κάθε nameserver που επιτρέπει zone transfer
    /// εκπέμπει πρόβλημα υψηλού κινδύνου και τα hostnames της ζώνης.
    /// </summary>
    /// <param name="e">Το domain-στόχος.</param>
    /// <param name="ctx">Το context του scan.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Ένα task που ολοκληρώνεται όταν ελεγχθούν όλοι οι nameservers.</returns>
    public async Task HandleAsync(ScanEvent e, ScanContext ctx, CancellationToken ct)
    {
        var ns = (await dns.QueryAsync(e.Data, QueryType.NS, cancellationToken: ct)).Answers.NsRecords()
            .Select(r => r.NSDName.Value.TrimEnd('.')).Distinct().ToList();
        var refused = 0;

        foreach (var server in ns)
        {
            var records = await TryAxfrAsync(e.Data, server, ct);
            if (records is null) { refused++; continue; }

            ctx.Emit(EventTypes.DnsIssue, $"{DnsIssues.ZoneTransfer} {server}: {records.Count} records", e, "high");
            var hosts = records.Select(r => r.DomainName.Value.TrimEnd('.')).Distinct().Take(MaxHosts);
            foreach (var host in hosts) ctx.Emit(EventTypes.Host, host, e);
        }
        ctx.Log($"Zone transfer: {ns.Count - refused} από {ns.Count} nameservers το επέτρεψαν.");
    }

    /// <summary>
    /// Ζητά AXFR από έναν nameserver (μέσω TCP, μόνο αν έχει δημόσια IP).
    /// </summary>
    /// <param name="domain">Το domain.</param>
    /// <param name="server">Ο nameserver.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Τα records της ζώνης, ή <c>null</c> αν ο nameserver αρνήθηκε ή δεν απάντησε.</returns>
    static async Task<List<DnsResourceRecord>?> TryAxfrAsync(string domain, string server, CancellationToken ct)
    {
        try
        {
            var ip = await NetGuard.ResolvePublicAsync(server, ct);
            var client = new LookupClient(new LookupClientOptions(new NameServer(ip))
            {
                UseTcpOnly = true,
                UseCache = false,
                Retries = 0,
                Timeout = TimeSpan.FromSeconds(10),
                ThrowDnsErrors = false,
            });
            var res = await client.QueryAsync(domain, QueryType.AXFR, cancellationToken: ct);
            // Μια πραγματική ζώνη ξεκινά με SOA και έχει κι άλλα records· η άρνηση έρχεται ως σφάλμα ή κενή απάντηση.
            return !res.HasError && res.Answers.Count > 1 && res.Answers.SoaRecords().Any() ? res.Answers.ToList() : null;
        }
        catch (Exception ex) when (ex is DnsResponseException or HttpRequestException or System.Net.Sockets.SocketException
                                       or OperationCanceledException && !ct.IsCancellationRequested)
        {
            return null;
        }
    }
}
