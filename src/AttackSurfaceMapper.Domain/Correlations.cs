using System.Text.RegularExpressions;

namespace AttackSurfaceMapper.Domain;

/// <summary>
/// Ένα συμπέρασμα που προκύπτει από τον συνδυασμό πολλών events (π.χ. "dev συστήματα εκτεθειμένα").
/// </summary>
/// <param name="RuleId">Το id του κανόνα.</param>
/// <param name="Title">Ο τίτλος, για το UI.</param>
/// <param name="Risk">Το επίπεδο κινδύνου (info, low, medium, high).</param>
/// <param name="Description">Τι σημαίνει και τι να κάνεις.</param>
/// <param name="EventIds">Τα events που οδήγησαν στο συμπέρασμα.</param>
public record Correlation(string RuleId, string Title, string Risk, string Description, IReadOnlyList<long> EventIds);

/// <summary>
/// Τα δεδομένα ενός scan σε μορφή βολική για τους κανόνες: events ανά τύπο, γονείς και παιδιά.
/// </summary>
public sealed class CorrelationInput
{
    readonly ILookup<long, long> _children;
    readonly ILookup<long, long> _parents;
    readonly ILookup<string, ScanEvent> _byType;

    /// <summary>Προετοιμάζει τα δεδομένα για τους κανόνες.</summary>
    /// <param name="events">Τα events του scan.</param>
    /// <param name="edges">Οι ακμές του γράφου.</param>
    public CorrelationInput(IReadOnlyList<ScanEvent> events, IReadOnlyList<Edge> edges)
    {
        ById = events.ToDictionary(e => e.Id);
        _byType = events.ToLookup(e => e.Type);
        _children = edges.ToLookup(e => e.From, e => e.To);
        _parents = edges.ToLookup(e => e.To, e => e.From);
    }

    /// <summary>Όλα τα events, ανά id.</summary>
    public IReadOnlyDictionary<long, ScanEvent> ById { get; }

    /// <summary>Επιστρέφει τα events ενός τύπου.</summary>
    /// <param name="type">Ο τύπος.</param>
    /// <returns>Τα events.</returns>
    public IEnumerable<ScanEvent> OfType(string type) => _byType[type];

    /// <summary>Επιστρέφει τα events που προέκυψαν από ένα event.</summary>
    /// <param name="id">Το id του event.</param>
    /// <returns>Τα παιδιά του.</returns>
    public IEnumerable<ScanEvent> Children(long id) => _children[id].Select(i => ById[i]);

    /// <summary>Επιστρέφει τα events από τα οποία προέκυψε ένα event (μπορεί να είναι πολλά).</summary>
    /// <param name="id">Το id του event.</param>
    /// <returns>Οι γονείς του.</returns>
    public IEnumerable<ScanEvent> Parents(long id) => _parents[id].Where(ById.ContainsKey).Select(i => ById[i]);
}

/// <summary>Ένας κανόνας συσχέτισης.</summary>
public interface ICorrelationRule
{
    /// <summary>Εξετάζει τα δεδομένα ενός scan.</summary>
    /// <param name="input">Τα δεδομένα.</param>
    /// <returns>Το συμπέρασμα, ή <c>null</c> αν ο κανόνας δεν ισχύει.</returns>
    Correlation? Evaluate(CorrelationInput input);
}

/// <summary>
/// Εκτελεί όλους τους κανόνες συσχέτισης σε ένα ολοκληρωμένο scan. Εμπνευσμένο από τους
/// κανόνες YAML του SpiderFoot (MIT), γραμμένο σε C# ώστε να ελέγχεται από τον compiler.
/// </summary>
public static class CorrelationEngine
{
    /// <summary>Όλοι οι κανόνες.</summary>
    public static readonly IReadOnlyList<ICorrelationRule> Rules =
    [
        new SecretsExposedRule(),
        new TakeoverRule(),
        new BlocklistedRule(),
        new EmailSpoofingRule(),
        new DevTestExposedRule(),
        new InternalIpRule(),
        new CertificateProblemsRule(),
        new SensitiveHistoricUrlsRule(),
        new ForgottenHostsRule(),
        new OutlierRule(EventTypes.Hosting, "outlier_hosting", "πάροχο hosting"),
        new OutlierRule(EventTypes.Geo, "outlier_country", "χώρα"),
    ];

    /// <summary>Εκτελεί όλους τους κανόνες και επιστρέφει όσα συμπεράσματα ισχύουν, από τον υψηλότερο κίνδυνο.</summary>
    /// <param name="events">Τα events του scan.</param>
    /// <param name="edges">Οι ακμές.</param>
    /// <returns>Τα συμπεράσματα.</returns>
    public static List<Correlation> Run(IReadOnlyList<ScanEvent> events, IReadOnlyList<Edge> edges)
    {
        var input = new CorrelationInput(events, edges);
        return Rules.Select(r => r.Evaluate(input)).OfType<Correlation>()
            .OrderByDescending(c => Array.IndexOf(EventTypes.Risks, c.Risk))
            .ToList();
    }

    /// <summary>
    /// Βοηθητική για κανόνες που απλώς συγκεντρώνουν όλα τα events ενός ή περισσότερων τύπων.
    /// </summary>
    /// <param name="input">Τα δεδομένα.</param>
    /// <param name="types">Οι τύποι.</param>
    /// <param name="make">Φτιάχνει το συμπέρασμα από τα events που βρέθηκαν.</param>
    /// <returns>Το συμπέρασμα, ή <c>null</c> αν δεν υπάρχει κανένα event.</returns>
    internal static Correlation? WhenAny(CorrelationInput input, string[] types, Func<List<ScanEvent>, Correlation> make)
    {
        var found = types.SelectMany(input.OfType).ToList();
        return found.Count == 0 ? null : make(found);
    }
}

/// <summary>Secrets σε repositories ή σε σελίδες/JavaScript του στόχου.</summary>
sealed class SecretsExposedRule : ICorrelationRule
{
    /// <inheritdoc/>
    public Correlation? Evaluate(CorrelationInput input)
    {
        var found = input.OfType(EventTypes.SecretInContent)
            .Concat(input.OfType(EventTypes.LeakedSecrets).Where(e => e.Risk == "high"))
            .ToList();
        return found.Count == 0 ? null : new Correlation("secrets_exposed", "Δημόσια διαθέσιμα secrets", "high",
            $"Βρέθηκαν secrets σε {found.Count} σημεία (repos ή κώδικας που σερβίρεται στον browser). " +
            "Θεώρησέ τα διαρρεύσαντα: κάνε rotation και μετά αφαίρεσέ τα.", found.Select(e => e.Id).ToList());
    }
}

/// <summary>Subdomains με CNAME προς υπηρεσίες που δεν υπάρχουν πια.</summary>
sealed class TakeoverRule : ICorrelationRule
{
    /// <inheritdoc/>
    public Correlation? Evaluate(CorrelationInput input) => CorrelationEngine.WhenAny(input, [EventTypes.Takeover], found =>
        new Correlation("subdomain_takeover", "Πιθανό subdomain takeover", "high",
            $"{found.Count} subdomain(s) δείχνουν σε υπηρεσίες που δεν υπάρχουν. Όποιος δημιουργήσει ξανά το όνομα " +
            "στην υπηρεσία ελέγχει το subdomain. Σβήσε τα DNS records ή ξαναδημιούργησε τους πόρους.",
            found.Select(e => e.Id).ToList()));
}

/// <summary>IPs ή hostnames του στόχου σε blocklists.</summary>
sealed class BlocklistedRule : ICorrelationRule
{
    /// <inheritdoc/>
    public Correlation? Evaluate(CorrelationInput input) => CorrelationEngine.WhenAny(input, [EventTypes.Malicious], found =>
        new Correlation("blocklisted", "Υποδομή σε blocklists", "high",
            $"{found.Count} IP/hostname(s) του στόχου εμφανίζονται σε λίστες κακόβουλης δραστηριότητας. " +
            "Μπορεί να έχουν παραβιαστεί ή να μοιράζονται υποδομή με κακόβουλους.", found.Select(e => e.Id).ToList()));
}

/// <summary>Το domain δεν έχει ούτε SPF ούτε DMARC (ή έχει SPF +all): το spoofing είναι εύκολο.</summary>
sealed class EmailSpoofingRule : ICorrelationRule
{
    /// <inheritdoc/>
    public Correlation? Evaluate(CorrelationInput input)
    {
        var issues = input.OfType(EventTypes.DnsIssue).ToList();
        bool Has(string text) => issues.Any(i => i.Data.StartsWith(text, StringComparison.Ordinal));
        var noSpf = Has(DnsIssues.NoSpf) || Has(DnsIssues.SpfAllowsAll);
        var noDmarc = Has(DnsIssues.NoDmarc) || Has(DnsIssues.DmarcNone);
        if (!noSpf || !noDmarc) return null;
        return new Correlation("email_spoofing", "Εύκολο email spoofing", "high",
            "Χωρίς αποτελεσματικό SPF και DMARC, οποιοσδήποτε μπορεί να στείλει πειστικά emails ως το domain " +
            "(phishing). Πρόσθεσε SPF με -all ή ~all και DMARC με p=quarantine ή p=reject.",
            issues.Select(i => i.Id).ToList());
    }
}

/// <summary>Συστήματα ανάπτυξης/δοκιμών (dev, test, staging…) προσβάσιμα από το Internet.</summary>
sealed partial class DevTestExposedRule : ICorrelationRule
{
    /// <summary>Labels που συνήθως δηλώνουν μη παραγωγικό σύστημα.</summary>
    [GeneratedRegex(@"(^|[.-])(dev|develop|test|testing|staging|stage|stg|uat|qa|preprod|sandbox|demo|beta)\d*([.-]|$)")]
    private static partial Regex DevLabel();

    /// <inheritdoc/>
    public Correlation? Evaluate(CorrelationInput input)
    {
        var found = input.OfType(EventTypes.Host)
            .Where(h => DevLabel().IsMatch(h.Data))
            .Where(h => input.Children(h.Id).Any(c => c.Type is EventTypes.Ip or EventTypes.Ip6))
            .ToList();
        return found.Count == 0 ? null : new Correlation("dev_test_exposed", "Dev/test συστήματα στο Internet", "medium",
            $"{found.Count} host(s) μοιάζουν με συστήματα ανάπτυξης ή δοκιμών και έχουν δημόσια IP. Συχνά έχουν " +
            "αδύναμη ασφάλεια, debug λειτουργίες ή αντίγραφα δεδομένων. Περιόρισέ τα με VPN ή IP allowlist.",
            found.Select(e => e.Id).ToList());
    }
}

/// <summary>Ιδιωτικές IP σε δημόσιο DNS: αποκαλύπτουν την εσωτερική δομή του δικτύου.</summary>
sealed class InternalIpRule : ICorrelationRule
{
    /// <inheritdoc/>
    public Correlation? Evaluate(CorrelationInput input) => CorrelationEngine.WhenAny(input, [EventTypes.InternalIp], found =>
        new Correlation("internal_ip_exposed", "Εσωτερικές IP σε δημόσιο DNS", "medium",
            $"{found.Count} ιδιωτική(ές) IP εμφανίζονται σε δημόσιο DNS και αποκαλύπτουν πληροφορίες για το εσωτερικό " +
            "δίκτυο. Χρησιμοποίησε split-horizon DNS για τα εσωτερικά ονόματα.", found.Select(e => e.Id).ToList()));
}

/// <summary>Ληγμένα, μη έμπιστα ή λάθος certificates.</summary>
sealed class CertificateProblemsRule : ICorrelationRule
{
    /// <inheritdoc/>
    public Correlation? Evaluate(CorrelationInput input) => CorrelationEngine.WhenAny(input,
        [EventTypes.CertExpired, EventTypes.CertExpiring, EventTypes.CertMismatch, EventTypes.CertUntrusted], found =>
        new Correlation("certificate_problems", "Προβλήματα certificates", found.Any(e => e.Type == EventTypes.CertExpired) ? "high" : "medium",
            $"{found.Count} πρόβλημα(τα) σε certificates. Οι χρήστες βλέπουν προειδοποιήσεις και μαθαίνουν να τις " +
            "αγνοούν, κάτι που διευκολύνει επιθέσεις man-in-the-middle. Αυτοματοποίησε την ανανέωση (π.χ. Let's Encrypt).",
            found.Select(e => e.Id).ToList()));
}

/// <summary>Παλιά URLs (Wayback) που δείχνουν σε ευαίσθητα αρχεία (backups, .env, βάσεις).</summary>
sealed class SensitiveHistoricUrlsRule : ICorrelationRule
{
    /// <inheritdoc/>
    public Correlation? Evaluate(CorrelationInput input)
    {
        var found = input.OfType(EventTypes.HistoricUrl).Where(e => e.Risk is "medium" or "high").ToList();
        return found.Count == 0 ? null : new Correlation("sensitive_historic_urls", "Ευαίσθητα αρχεία στο αρχείο του Internet", "medium",
            $"Το Wayback Machine έχει καταγράψει {found.Count} URL(s) με ευαίσθητα αρχεία (backups, config, βάσεις). " +
            "Έλεγξε αν υπάρχουν ακόμα στον server και αν τα δεδομένα τους είναι ακόμα ενεργά.", found.Select(e => e.Id).ToList());
    }
}

/// <summary>
/// Hostnames που υπάρχουν μόνο σε certificates και δεν έχουν πια DNS: πιθανά ξεχασμένα συστήματα,
/// που μπορεί να ξαναζωντανέψουν ή να δείχνουν παλιά υποδομή.
/// </summary>
sealed class ForgottenHostsRule : ICorrelationRule
{
    /// <inheritdoc/>
    public Correlation? Evaluate(CorrelationInput input)
    {
        var found = input.OfType(EventTypes.HostUnresolved)
            .Where(u => input.ById.Values.Any(h => h.Type == EventTypes.Host && h.Data == u.Data && h.Module == "cert_transparency"))
            .ToList();
        return found.Count == 0 ? null : new Correlation("forgotten_hosts", "Πιθανά ξεχασμένα hosts", "low",
            $"{found.Count} hostname(s) βρέθηκαν μόνο σε παλιά certificates και δεν έχουν πια DNS. Αν κάποιο " +
            "ξαναχρησιμοποιηθεί, βεβαιώσου ότι δεν δείχνει σε ξεχασμένη υποδομή.", found.Select(e => e.Id).ToList());
    }
}

/// <summary>
/// Μια τιμή (π.χ. πάροχος ή χώρα) που εμφανίζεται σε πολύ λίγες IP σε σχέση με τις υπόλοιπες:
/// συχνά είναι shadow IT ή σύστημα που στήθηκε εκτός της κανονικής υποδομής.
/// </summary>
/// <param name="type">Ο τύπος που εξετάζεται (Hosting ή Geo).</param>
/// <param name="ruleId">Το id του κανόνα.</param>
/// <param name="label">Η ελληνική ονομασία της τιμής, για το μήνυμα.</param>
sealed class OutlierRule(string type, string ruleId, string label) : ICorrelationRule
{
    /// <summary>Πόσες IP χρειάζονται τουλάχιστον για να έχει νόημα η σύγκριση.</summary>
    const int MinIps = 5;

    /// <inheritdoc/>
    public Correlation? Evaluate(CorrelationInput input)
    {
        // Πόσες IP "δείχνουν" σε κάθε τιμή (μια τιμή μπορεί να έχει πολλούς γονείς: όλες τις IP του παρόχου).
        var values = input.OfType(type)
            .Select(v => (Event: v, Ips: input.Parents(v.Id).Count(p => p.Type is EventTypes.Ip or EventTypes.Ip6)))
            .Where(x => x.Ips > 0)
            .ToList();
        var total = values.Sum(x => x.Ips);
        if (total < MinIps || values.Count < 2) return null;

        var outliers = values.Where(x => x.Ips == 1 && x.Ips * 10 < total).Select(x => x.Event).ToList();
        return outliers.Count == 0 ? null : new Correlation(ruleId, $"Ασυνήθιστη {label}", "low",
            $"{string.Join(", ", outliers.Select(o => o.Data))}: εμφανίζεται σε μία μόνο από τις {total} IP. " +
            "Μπορεί να είναι σύστημα εκτός της κανονικής υποδομής (shadow IT) που αξίζει έλεγχο.",
            outliers.Select(e => e.Id).ToList());
    }
}
