using System.Globalization;
using System.Text.RegularExpressions;

namespace AttackSurfaceMapper.Domain;

/// <summary>
/// Αποφασίζει τι ανήκει στον στόχο και κανονικοποιεί τα hostnames.
/// </summary>
/// <remarks>
/// Ένα hostname είναι "in scope" αν είναι το ίδιο το domain ή subdomain του. Όλα τα υπόλοιπα
/// γίνονται AFFILIATE και δεν εξερευνώνται περαιτέρω. Αλλιώς ένα scan του example.com θα
/// κατέληγε να σκανάρει το cloudflare.com.
/// </remarks>
public static partial class Scope
{
    static readonly IdnMapping Idn = new();

    /// <summary>Regex για έγκυρο hostname (labels 1–63 χαρακτήρων, σύνολο έως 253).</summary>
    [GeneratedRegex(@"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")]
    private static partial Regex HostRegex();

    /// <summary>
    /// Κανονικοποιεί ένα hostname: πεζά γράμματα, χωρίς τελεία στο τέλος, χωρίς "*." μπροστά,
    /// και IDN (π.χ. ελληνικά) σε punycode.
    /// </summary>
    /// <param name="raw">Το hostname όπως ήρθε από την πηγή.</param>
    /// <returns>Το κανονικοποιημένο hostname, ή <c>null</c> αν δεν είναι έγκυρο.</returns>
    public static string? NormalizeHost(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var h = raw.Trim().TrimEnd('.').ToLowerInvariant();
        if (h.StartsWith("*.")) h = h[2..];
        try { h = Idn.GetAscii(h); } catch (ArgumentException) { return null; }
        return HostRegex().IsMatch(h) ? h : null;
    }

    /// <summary>
    /// Ελέγχει αν ένα hostname ανήκει στον στόχο, δηλαδή αν είναι το ίδιο το domain ή subdomain του.
    /// </summary>
    /// <param name="host">Κανονικοποιημένο hostname.</param>
    /// <param name="target">Το κανονικοποιημένο domain-στόχος.</param>
    /// <returns><c>true</c> αν ο host είναι μέσα στο scope.</returns>
    public static bool InScope(string host, string target) =>
        host == target || host.EndsWith("." + target, StringComparison.Ordinal);

    // Δεύτερου επιπέδου TLDs: για το example.co.uk το "όνομα" του οργανισμού είναι το "example".
    static readonly HashSet<string> SecondLevel =
    [
        "co.uk", "org.uk", "ac.uk", "gov.uk", "com.gr", "gov.gr", "edu.gr", "org.gr", "net.gr",
        "com.au", "net.au", "org.au", "co.jp", "co.nz", "com.br", "com.cy", "co.za", "com.tr", "com.mx"
    ];

    /// <summary>
    /// Ελέγχει αν ένα όνομα είναι γνωστό TLD δεύτερου επιπέδου (π.χ. "co.uk", "com.gr"), δηλαδή
    /// κατάληξη και όχι domain οργανισμού.
    /// </summary>
    /// <param name="name">Κανονικοποιημένο όνομα.</param>
    /// <returns><c>true</c> αν είναι TLD δεύτερου επιπέδου.</returns>
    public static bool IsSecondLevelSuffix(string name) => SecondLevel.Contains(name);

    /// <summary>
    /// Βγάζει το πιθανό όνομα του οργανισμού από ένα domain, π.χ. "example" από "www.example.co.uk".
    /// Χρησιμοποιείται για την αναζήτηση του οργανισμού στο GitHub.
    /// </summary>
    /// <param name="domain">Κανονικοποιημένο domain.</param>
    /// <returns>Το label πριν από το TLD.</returns>
    public static string OrgLabel(string domain)
    {
        var parts = domain.Split('.');
        if (parts.Length >= 3 && SecondLevel.Contains(string.Join('.', parts[^2..]))) return parts[^3];
        return parts.Length >= 2 ? parts[^2] : parts[0];
    }
}
