using AttackSurfaceMapper.Engine;
using DnsClient;

namespace AttackSurfaceMapper.Modules;

/// <summary>
/// Διαβάζει τα MX, NS και TXT records του domain, ελέγχει SPF και DMARC, και αναγνωρίζει
/// τις SaaS υπηρεσίες που χρησιμοποιεί ο οργανισμός.
/// </summary>
/// <remarks>
/// Τα TXT records "verification" (π.χ. <c>google-site-verification</c>) και τα includes του SPF
/// αποκαλύπτουν ποιες υπηρεσίες χρησιμοποιεί ένας οργανισμός: κάθε μία είναι μέρος του attack surface.
/// </remarks>
public sealed class DnsRecordsModule : IModule
{
    /// <inheritdoc/>
    public string Name => "dns_records";
    /// <inheritdoc/>
    public string Description => "MX, NS, TXT, έλεγχος SPF/DMARC και αναγνώριση SaaS υπηρεσιών.";
    /// <inheritdoc/>
    public Footprint Level => Footprint.Passive;
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Watched { get; } = [EventTypes.Domain];
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Produced { get; } =
        [EventTypes.MailProvider, EventTypes.DnsProvider, EventTypes.DnsText, EventTypes.Spf, EventTypes.Dmarc,
         EventTypes.DnsIssue, EventTypes.Saas, EventTypes.Host, EventTypes.AffiliateHost];

    /// <summary>
    /// Διαβάζει όλα τα records του domain και εκπέμπει providers, SaaS υπηρεσίες και προβλήματα ρύθμισης.
    /// </summary>
    /// <param name="e">Το domain-στόχος.</param>
    /// <param name="ctx">Το context του scan.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Ένα task που ολοκληρώνεται όταν τελειώσουν τα DNS ερωτήματα.</returns>
    public async Task HandleAsync(ScanEvent e, ScanContext ctx, CancellationToken ct)
    {
        await MxAsync(e, ctx, ct);
        await NsAsync(e, ctx, ct);
        var txt = await TxtAsync(e.Data, ctx, ct);
        foreach (var t in txt)
        {
            ctx.Emit(EventTypes.DnsText, t, e);
            foreach (var (marker, service) in TxtServices)
                if (t.StartsWith(marker, StringComparison.OrdinalIgnoreCase)) ctx.Emit(EventTypes.Saas, service, e);
        }
        CheckSpf(e, txt, ctx);
        await CheckDmarcAsync(e, ctx, ct);
    }

    /// <summary>Διαβάζει τα MX records: mail servers και πάροχος email (Google, Microsoft…).</summary>
    /// <param name="e">Το domain.</param>
    /// <param name="ctx">Το context του scan.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Ένα task που ολοκληρώνεται όταν τελειώσει το ερώτημα.</returns>
    static async Task MxAsync(ScanEvent e, ScanContext ctx, CancellationToken ct)
    {
        var res = await ctx.Dns.QueryAsync(e.Data, QueryType.MX, cancellationToken: ct);
        foreach (var mx in res.Answers.MxRecords())
        {
            var host = mx.Exchange.Value.TrimEnd('.').ToLowerInvariant();
            if (host.Length == 0) continue;   // "null MX": το domain δεν δέχεται email
            ctx.Emit(EventTypes.MailProvider, host, e);
            ctx.Emit(EventTypes.Host, host, e);
            foreach (var (suffix, service) in MxServices)
                if (host.EndsWith(suffix, StringComparison.Ordinal)) ctx.Emit(EventTypes.Saas, service, e);
        }
    }

    /// <summary>Διαβάζει τα NS records: nameservers και πάροχος DNS.</summary>
    /// <param name="e">Το domain.</param>
    /// <param name="ctx">Το context του scan.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Ένα task που ολοκληρώνεται όταν τελειώσει το ερώτημα.</returns>
    static async Task NsAsync(ScanEvent e, ScanContext ctx, CancellationToken ct)
    {
        var res = await ctx.Dns.QueryAsync(e.Data, QueryType.NS, cancellationToken: ct);
        foreach (var ns in res.Answers.NsRecords())
        {
            var host = ns.NSDName.Value.TrimEnd('.').ToLowerInvariant();
            ctx.Emit(EventTypes.DnsProvider, host, e);
            ctx.Emit(EventTypes.Host, host, e);
        }
    }

    /// <summary>Επιστρέφει όλα τα TXT records ενός ονόματος (ενωμένα, αν είναι σπασμένα σε κομμάτια).</summary>
    /// <param name="name">Το όνομα για το οποίο ζητάμε TXT.</param>
    /// <param name="ctx">Το context του scan.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Τα TXT records.</returns>
    static async Task<List<string>> TxtAsync(string name, ScanContext ctx, CancellationToken ct)
    {
        var res = await ctx.Dns.QueryAsync(name, QueryType.TXT, cancellationToken: ct);
        return res.Answers.TxtRecords().Select(r => string.Concat(r.Text)).ToList();
    }

    /// <summary>
    /// Ελέγχει το SPF: αν υπάρχει, αν είναι μοναδικό, αν επιτρέπει σε όλους να στέλνουν
    /// email (<c>+all</c>), και ποιες υπηρεσίες περιλαμβάνει.
    /// </summary>
    /// <param name="e">Το domain.</param>
    /// <param name="txt">Τα TXT records του domain.</param>
    /// <param name="ctx">Το context του scan.</param>
    static void CheckSpf(ScanEvent e, List<string> txt, ScanContext ctx)
    {
        var spf = txt.Where(t => t.StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase)).ToList();
        if (spf.Count == 0)
        {
            ctx.Emit(EventTypes.DnsIssue, "Δεν υπάρχει SPF: οποιοσδήποτε μπορεί να στείλει email ως " + e.Data, e, "medium");
            return;
        }
        if (spf.Count > 1)
            ctx.Emit(EventTypes.DnsIssue, "Πολλαπλά SPF records: σύμφωνα με το RFC 7208 το SPF θεωρείται άκυρο", e, "medium");

        foreach (var record in spf)
        {
            var all = record.Split(' ', StringSplitOptions.RemoveEmptyEntries).LastOrDefault(t => t.EndsWith("all"));
            var risk = all switch
            {
                "+all" or "all" => "high",
                "?all" => "medium",
                null => "medium",
                _ => null
            };
            ctx.Emit(EventTypes.Spf, record, e, risk);
            if (risk == "high") ctx.Emit(EventTypes.DnsIssue, "Το SPF επιτρέπει σε ΟΛΟΥΣ να στέλνουν email (+all)", e, "high");

            foreach (var (include, service) in SpfServices)
                if (record.Contains("include:" + include, StringComparison.OrdinalIgnoreCase)) ctx.Emit(EventTypes.Saas, service, e);
        }
    }

    /// <summary>
    /// Ελέγχει το DMARC (<c>_dmarc.domain</c>): αν υπάρχει και αν η πολιτική προστατεύει
    /// πραγματικά (το <c>p=none</c> μόνο παρακολουθεί, δεν μπλοκάρει τίποτα).
    /// </summary>
    /// <param name="e">Το domain.</param>
    /// <param name="ctx">Το context του scan.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Ένα task που ολοκληρώνεται όταν τελειώσει το ερώτημα.</returns>
    static async Task CheckDmarcAsync(ScanEvent e, ScanContext ctx, CancellationToken ct)
    {
        var dmarc = (await TxtAsync("_dmarc." + e.Data, ctx, ct))
            .FirstOrDefault(t => t.StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase));
        if (dmarc is null)
        {
            ctx.Emit(EventTypes.DnsIssue, "Δεν υπάρχει DMARC: τα πλαστά emails δεν απορρίπτονται", e, "medium");
            return;
        }
        var policy = dmarc.Split(';').Select(p => p.Trim())
            .FirstOrDefault(p => p.StartsWith("p=", StringComparison.OrdinalIgnoreCase))?[2..].ToLowerInvariant();
        var risk = policy is "none" or null ? "low" : null;
        ctx.Emit(EventTypes.Dmarc, dmarc, e, risk);
        if (risk is not null)
            ctx.Emit(EventTypes.DnsIssue, "DMARC με p=none: μόνο παρακολούθηση, τα πλαστά emails παραδίδονται", e, "low");
    }

    /// <summary>TXT records επαλήθευσης που αποκαλύπτουν υπηρεσίες.</summary>
    static readonly (string Marker, string Service)[] TxtServices =
    [
        ("google-site-verification=", "Google (Search Console / Workspace)"),
        ("MS=", "Microsoft 365"),
        ("facebook-domain-verification=", "Facebook / Meta Business"),
        ("apple-domain-verification=", "Apple"),
        ("atlassian-domain-verification=", "Atlassian (Jira / Confluence)"),
        ("docusign=", "DocuSign"),
        ("adobe-idp-site-verification=", "Adobe"),
        ("stripe-verification=", "Stripe"),
        ("zoom-domain-verification", "Zoom"),
        ("slack-domain-verification=", "Slack"),
        ("hubspot-developer-verification=", "HubSpot"),
        ("globalsign-domain-verification=", "GlobalSign"),
        ("dropbox-domain-verification=", "Dropbox"),
        ("onetrust-domain-verification=", "OneTrust"),
        ("mailru-verification", "Mail.ru"),
        ("yandex-verification", "Yandex"),
        ("cisco-ci-domain-verification=", "Cisco Webex"),
        ("openai-domain-verification=", "OpenAI"),
    ];

    /// <summary>Includes του SPF και η υπηρεσία που αντιστοιχούν.</summary>
    static readonly (string Include, string Service)[] SpfServices =
    [
        ("_spf.google.com", "Google Workspace"), ("spf.protection.outlook.com", "Microsoft 365"),
        ("sendgrid.net", "SendGrid"), ("mailgun.org", "Mailgun"), ("amazonses.com", "Amazon SES"),
        ("servers.mcsv.net", "Mailchimp"), ("mail.zendesk.com", "Zendesk"), ("_spf.salesforce.com", "Salesforce"),
        ("spf.mandrillapp.com", "Mandrill"), ("_spf.atlassian.net", "Atlassian"), ("spf.brevo.com", "Brevo"),
        ("zoho.com", "Zoho Mail"), ("_spf.mx.cloudflare.net", "Cloudflare Email Routing"),
    ];

    /// <summary>Καταλήξεις MX και ο πάροχος email που αντιστοιχούν.</summary>
    static readonly (string Suffix, string Service)[] MxServices =
    [
        ("google.com", "Google Workspace"), ("googlemail.com", "Google Workspace"),
        ("mail.protection.outlook.com", "Microsoft 365"), ("pphosted.com", "Proofpoint"),
        ("mimecast.com", "Mimecast"), ("zoho.com", "Zoho Mail"), ("zoho.eu", "Zoho Mail"),
        ("protonmail.ch", "Proton Mail"), ("mx.cloudflare.net", "Cloudflare Email Routing"),
    ];
}
