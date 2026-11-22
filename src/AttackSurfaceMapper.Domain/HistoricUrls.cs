using System.Text.RegularExpressions;

namespace AttackSurfaceMapper.Domain;

/// <summary>Η αξιολόγηση ενός παλιού URL.</summary>
/// <param name="Url">Το URL, χωρίς τιμές στο query string (μπορεί να περιέχουν tokens).</param>
/// <param name="Reason">Γιατί είναι ενδιαφέρον.</param>
/// <param name="Risk">Το επίπεδο κινδύνου.</param>
public record HistoricUrlFinding(string Url, string Reason, string Risk);

/// <summary>
/// Αξιολογεί URLs από το αρχείο του Internet (Wayback Machine): ποια δείχνουν σε ευαίσθητα
/// αρχεία, backups ή διαχειριστικά panels.
/// </summary>
public static partial class HistoricUrls
{
    /// <summary>Ένας κανόνας αξιολόγησης.</summary>
    /// <param name="Regex">Το regex πάνω στο path (πεζά).</param>
    /// <param name="Reason">Η εξήγηση.</param>
    /// <param name="Risk">Ο κίνδυνος.</param>
    record Rule(Regex Regex, string Reason, string Risk);

    static readonly Rule[] Rules =
    [
        new(new(@"(^|/)\.env(\.|$)|(^|/)\.git/(config|head)$|(^|/)\.htpasswd$|(^|/)id_[rd]sa$|\.pem$|\.key$|\.p12$|\.pfx$", RegexOptions.Compiled),
            "Αρχείο με credentials ή κλειδιά", "high"),
        new(new(@"\.(sql|sql\.gz|sql\.zip|dump|db|sqlite|mdb|bak|backup)$|wp-config\.php\.|\.php~$", RegexOptions.Compiled),
            "Backup ή βάση δεδομένων", "high"),
        // Συμπιεσμένα αρχεία μόνο όταν το όνομα μοιάζει με backup (backup.zip, site.tar.gz, db-2024.zip, www.rar).
        // Τα releases με αριθμό έκδοσης (app-1.2.3.tgz) είναι κανονικά downloads, όχι διαρροή.
        new(new(@"(^|/)[^/]*(backup|bak|dump|db|database|site|www|html|public_html|htdocs|wwwroot|full|export|old|archive|\d{4}-?\d{2}-?\d{2})[^/]*\.(zip|tar|tgz|tar\.gz|rar|7z|gz)$", RegexOptions.Compiled),
            "Συμπιεσμένο αρχείο με όνομα backup", "medium"),
        new(new(@"\.(old|orig|swp|save|tmp)$|(^|/)(web\.config|phpinfo\.php|server-status|\.ds_store)$", RegexOptions.Compiled),
            "Αρχείο ρυθμίσεων ή προσωρινό", "medium"),
        new(new(@"(^|/)(error|access|debug|app|application|laravel|php_errors?)[^/]*\.log$", RegexOptions.Compiled),
            "Log εφαρμογής ή server", "medium"),
        new(new(@"\.(xls|xlsx|csv)$", RegexOptions.Compiled), "Εξαγωγή δεδομένων", "medium"),
        new(new(@"(^|/)(admin|administrator|wp-admin|phpmyadmin|adminer|manager|cpanel|webmail|login)(/|\.php|$)", RegexOptions.Compiled),
            "Διαχειριστικό panel ή σελίδα σύνδεσης", "low"),
        new(new(@"(^|/)(swagger(-ui)?|api-docs|openapi\.json|graphql|graphiql|actuator)(/|\.|$)", RegexOptions.Compiled),
            "Τεκμηρίωση ή endpoint API", "low"),
    ];

    /// <summary>Ονόματα παραμέτρων που συνήθως περιέχουν credentials.</summary>
    [GeneratedRegex(@"^(token|access_token|api_?key|apikey|key|secret|password|passwd|pwd|auth|session|sid|signature|sig)$", RegexOptions.IgnoreCase)]
    private static partial Regex SensitiveParam();

    /// <summary>
    /// Αξιολογεί ένα URL. Αφαιρεί τις τιμές του query string (τις κρύβει), και σημειώνει ως
    /// ευαίσθητο ένα URL που περνά credentials στο query.
    /// </summary>
    /// <param name="raw">Το URL όπως το κατέγραψε το Wayback.</param>
    /// <returns>Η αξιολόγηση, ή <c>null</c> αν το URL δεν είναι ενδιαφέρον ή δεν είναι έγκυρο.</returns>
    public static HistoricUrlFinding? Evaluate(string raw)
    {
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https")) return null;
        var path = Uri.UnescapeDataString(uri.AbsolutePath).ToLowerInvariant();
        // Το Wayback έχει συχνά "κολλημένα" URLs (π.χ. /page.htmlhttp://other.com/...): δεν είναι πραγματικά αρχεία.
        if (path.Contains("http:") || path.Contains("https:")) return null;

        var parameters = uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Split('=', 2)[0]).ToList();
        var query = parameters.Count == 0 ? "" : "?" + string.Join("&", parameters.Select(p => p + "=•••"));
        var clean = $"{uri.Scheme}://{uri.Host}{uri.AbsolutePath}{query}";

        foreach (var rule in Rules)
            if (rule.Regex.IsMatch(path)) return new HistoricUrlFinding(clean, rule.Reason, rule.Risk);
        if (parameters.Any(p => SensitiveParam().IsMatch(p)))
            return new HistoricUrlFinding(clean, "Credentials στο URL (query string)", "medium");
        return null;
    }
}
