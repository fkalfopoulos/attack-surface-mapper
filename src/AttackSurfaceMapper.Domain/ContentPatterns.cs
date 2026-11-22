using System.Text.RegularExpressions;

namespace AttackSurfaceMapper.Domain;

/// <summary>Ένα secret που βρέθηκε σε περιεχόμενο, ήδη με απόκρυψη.</summary>
/// <param name="Kind">Το είδος (π.χ. "AWS Access Key").</param>
/// <param name="Masked">Το secret με ορατούς μόνο τους τελευταίους χαρακτήρες.</param>
/// <param name="Risk">Το επίπεδο κινδύνου.</param>
public record ContentSecret(string Kind, string Masked, string Risk);

/// <summary>
/// Αναγνώριση secrets, emails και cloud buckets μέσα σε κείμενο (HTML, JavaScript).
/// </summary>
/// <remarks>
/// Τα patterns είναι επιλεγμένα για υψηλή ακρίβεια (λίγα false positives): μόνο μορφές με
/// χαρακτηριστικό πρόθεμα (AKIA…, ghp_…, sk_live_…). Για πλήρη έλεγχο κώδικα χρησιμοποίησε το Gitleaks Scanner.
/// Τα secrets επιστρέφονται ΠΑΝΤΑ με απόκρυψη· η πλήρης τιμή δεν φεύγει ποτέ από αυτή την κλάση.
/// </remarks>
public static partial class ContentPatterns
{
    /// <summary>Ένα pattern για secret.</summary>
    /// <param name="Kind">Το είδος.</param>
    /// <param name="Regex">Το regex.</param>
    /// <param name="Risk">Ο κίνδυνος αν βρεθεί σε δημόσια σελίδα.</param>
    record SecretPattern(string Kind, Regex Regex, string Risk);

    static readonly SecretPattern[] SecretPatterns =
    [
        new("AWS Access Key", new(@"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", RegexOptions.Compiled), "high"),
        new("GitHub token", new(@"\bgh[pousr]_[0-9A-Za-z]{36}\b|\bgithub_pat_[0-9A-Za-z_]{82}\b", RegexOptions.Compiled), "high"),
        new("Stripe secret key", new(@"\b[sr]k_live_[0-9A-Za-z]{24,}\b", RegexOptions.Compiled), "high"),
        new("Slack token", new(@"\bxox[abprs]-[0-9A-Za-z-]{10,}\b", RegexOptions.Compiled), "high"),
        new("Slack webhook", new(@"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+", RegexOptions.Compiled), "high"),
        new("SendGrid API key", new(@"\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b", RegexOptions.Compiled), "high"),
        new("OpenAI API key", new(@"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b", RegexOptions.Compiled), "high"),
        new("Anthropic API key", new(@"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}", RegexOptions.Compiled), "high"),
        new("Private key", new(@"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", RegexOptions.Compiled), "high"),
        // Τα Google API keys μπαίνουν συχνά σκόπιμα σε frontend (π.χ. Maps), περιορισμένα ανά referrer:
        // μεσαίος κίνδυνος, γιατί χρειάζεται έλεγχος αν έχουν περιορισμούς.
        new("Google API key", new(@"\bAIza[0-9A-Za-z_-]{35}\b", RegexOptions.Compiled), "medium"),
    ];

    /// <summary>Εντοπίζει email διευθύνσεις.</summary>
    [GeneratedRegex(@"\b[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9-]+\.)+[A-Za-z]{2,24}\b")]
    private static partial Regex EmailRegex();

    /// <summary>Εντοπίζει URLs και ονόματα cloud storage (S3, Azure Blob, Google Cloud Storage, DigitalOcean Spaces).</summary>
    [GeneratedRegex(@"\b(?:[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com|s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com/[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]|[a-z0-9]{3,24}\.blob\.core\.windows\.net|storage\.googleapis\.com/[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]|[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.storage\.googleapis\.com|[a-z0-9-]{3,63}\.[a-z0-9-]+\.digitaloceanspaces\.com)", RegexOptions.IgnoreCase)]
    private static partial Regex BucketRegex();

    /// <summary>Καταλήξεις αρχείων που μοιάζουν με email αλλά δεν είναι (π.χ. "logo@2x.png").</summary>
    static readonly HashSet<string> FakeEmailTlds = ["png", "jpg", "jpeg", "gif", "svg", "webp", "js", "css", "map", "woff", "woff2"];

    /// <summary>
    /// Βρίσκει secrets σε ένα κείμενο και τα επιστρέφει με απόκρυψη, ένα ανά διαφορετική τιμή.
    /// </summary>
    /// <param name="text">Το κείμενο (HTML ή JavaScript).</param>
    /// <returns>Τα secrets, με απόκρυψη.</returns>
    public static List<ContentSecret> FindSecrets(string text)
    {
        var found = new List<ContentSecret>();
        var seen = new HashSet<string>();
        foreach (var p in SecretPatterns)
            foreach (Match m in p.Regex.Matches(text))
                if (seen.Add(m.Value))
                    found.Add(new ContentSecret(p.Kind, p.Kind == "Private key" ? "-----BEGIN … PRIVATE KEY-----" : Mask(m.Value), p.Risk));
        return found;
    }

    /// <summary>Βρίσκει email διευθύνσεις, αγνοώντας ονόματα αρχείων που μοιάζουν με email.</summary>
    /// <param name="text">Το κείμενο.</param>
    /// <returns>Τα emails, με πεζά, χωρίς διπλότυπα.</returns>
    public static List<string> FindEmails(string text) => EmailRegex().Matches(text)
        .Select(m => m.Value.ToLowerInvariant())
        .Where(e => !FakeEmailTlds.Contains(e[(e.LastIndexOf('.') + 1)..]))
        .Distinct()
        .ToList();

    /// <summary>Βρίσκει αναφορές σε cloud storage buckets.</summary>
    /// <param name="text">Το κείμενο.</param>
    /// <returns>Τα buckets, με πεζά, χωρίς διπλότυπα.</returns>
    public static List<string> FindBuckets(string text) => BucketRegex().Matches(text)
        .Select(m => m.Value.ToLowerInvariant().TrimEnd('.'))
        .Distinct()
        .ToList();

    /// <summary>
    /// Κρύβει ένα secret αφήνοντας ορατούς μόνο τους τελευταίους χαρακτήρες: το πολύ 6 και ποτέ
    /// πάνω από το 1/4 του μήκους (ίδιος κανόνας με το Gitleaks Scanner).
    /// </summary>
    /// <param name="secret">Το secret.</param>
    /// <returns>Π.χ. "••••••ABCD12".</returns>
    public static string Mask(string secret)
    {
        var show = Math.Min(6, secret.Length / 4);
        return "••••••" + (show == 0 ? "" : secret[^show..]);
    }
}
