using System.Net;
using AttackSurfaceMapper.Engine;
using DnsClient;
using DnsClient.Protocol;

namespace AttackSurfaceMapper.Modules;

/// <summary>
/// Βρίσκει τις IP (A/AAAA) και τα CNAME κάθε hostname, και εντοπίζει πιθανά subdomain takeovers.
/// </summary>
/// <remarks>
/// Subdomain takeover: ένα subdomain έχει CNAME προς μια υπηρεσία (π.χ. <c>app.herokuapp.com</c>)
/// που δεν υπάρχει πια. Όποιος δημιουργήσει ξανά εκείνο το όνομα στην υπηρεσία ελέγχει το subdomain.
/// Ο έλεγχος εδώ είναι παθητικός: κοιτάμε μόνο αν το CNAME δείχνει σε NXDOMAIN.
/// </remarks>
public sealed class DnsResolveModule : IModule
{
    /// <inheritdoc/>
    public string Name => "dns_resolve";
    /// <inheritdoc/>
    public string Description => "IP διευθύνσεις και CNAME κάθε hostname· εντοπίζει πιθανά subdomain takeovers.";
    /// <inheritdoc/>
    public Footprint Level => Footprint.Passive;
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Watched { get; } = [EventTypes.Domain, EventTypes.Host];
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Produced { get; } =
        [EventTypes.Ip, EventTypes.Ip6, EventTypes.InternalIp, EventTypes.Host, EventTypes.AffiliateHost,
         EventTypes.HostUnresolved, EventTypes.Takeover];

    /// <summary>
    /// Κάνει resolve ένα hostname σε IPv4/IPv6, ακολουθεί τα CNAME και σημειώνει τους hosts χωρίς DNS.
    /// </summary>
    /// <param name="e">Το hostname (DOMAIN_NAME ή INTERNET_NAME).</param>
    /// <param name="ctx">Το context του scan.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Ένα task που ολοκληρώνεται όταν τελειώσουν τα DNS ερωτήματα.</returns>
    public async Task HandleAsync(ScanEvent e, ScanContext ctx, CancellationToken ct)
    {
        var a = await ctx.Dns.QueryAsync(e.Data, QueryType.A, cancellationToken: ct);
        var aaaa = await ctx.Dns.QueryAsync(e.Data, QueryType.AAAA, cancellationToken: ct);

        var addresses = a.Answers.ARecords().Select(r => r.Address)
            .Concat(aaaa.Answers.AaaaRecords().Select(r => r.Address))
            .Distinct()
            .ToList();
        var cnames = a.Answers.CnameRecords().Select(r => r.CanonicalName.Value).Distinct().ToList();

        foreach (var cname in cnames) ctx.Emit(EventTypes.Host, cname, e);

        foreach (var ip in addresses)
        {
            if (!NetGuard.IsPublic(ip))
                ctx.Emit(EventTypes.InternalIp, ip.ToString(), e, risk: "medium");
            else
                ctx.Emit(ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? EventTypes.Ip6 : EventTypes.Ip,
                    ip.ToString(), e);
        }

        if (addresses.Count == 0)
        {
            ctx.Emit(EventTypes.HostUnresolved, e.Data, e, risk: "info");
            foreach (var cname in cnames) await CheckTakeoverAsync(e, cname, ctx, ct);
        }
    }

    /// <summary>
    /// Ελέγχει αν ένα CNAME δείχνει σε όνομα που δεν υπάρχει (NXDOMAIN), δηλαδή πιθανό subdomain takeover.
    /// </summary>
    /// <param name="e">Το hostname που έχει το CNAME.</param>
    /// <param name="cname">Ο στόχος του CNAME.</param>
    /// <param name="ctx">Το context του scan.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Ένα task που ολοκληρώνεται όταν τελειώσει ο έλεγχος.</returns>
    static async Task CheckTakeoverAsync(ScanEvent e, string cname, ScanContext ctx, CancellationToken ct)
    {
        var name = cname.TrimEnd('.');
        var res = await ctx.Dns.QueryAsync(name, QueryType.A, cancellationToken: ct);
        if (res.Header.ResponseCode != DnsHeaderResponseCode.NotExistentDomain) return;

        var service = TakeoverServices.FirstOrDefault(s => name.EndsWith(s.Suffix, StringComparison.OrdinalIgnoreCase));
        var risk = service.Name is null ? "medium" : "high";
        var label = service.Name is null ? "άγνωστη υπηρεσία" : service.Name;
        ctx.Emit(EventTypes.Takeover, $"{e.Data} → {name} ({label}, NXDOMAIN)", e, risk);
    }

    /// <summary>Υπηρεσίες όπου ένα "ορφανό" CNAME μπορεί συνήθως να καταληφθεί.</summary>
    static readonly (string Suffix, string Name)[] TakeoverServices =
    [
        (".herokuapp.com", "Heroku"), (".herokudns.com", "Heroku"),
        (".github.io", "GitHub Pages"), (".azurewebsites.net", "Azure App Service"),
        (".cloudapp.net", "Azure"), (".cloudapp.azure.com", "Azure"), (".trafficmanager.net", "Azure Traffic Manager"),
        (".blob.core.windows.net", "Azure Blob"), (".s3.amazonaws.com", "AWS S3"),
        (".elasticbeanstalk.com", "AWS Elastic Beanstalk"), (".netlify.app", "Netlify"),
        (".vercel.app", "Vercel"), (".surge.sh", "Surge"), (".bitbucket.io", "Bitbucket"),
        (".ghost.io", "Ghost"), (".myshopify.com", "Shopify"), (".pantheonsite.io", "Pantheon"),
        (".wpengine.com", "WP Engine"), (".fly.dev", "Fly.io"), (".readthedocs.io", "Read the Docs"),
    ];
}
