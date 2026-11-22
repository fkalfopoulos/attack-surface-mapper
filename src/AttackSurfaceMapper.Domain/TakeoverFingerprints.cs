namespace AttackSurfaceMapper.Domain;

/// <summary>Τα χαρακτηριστικά μιας υπηρεσίας όπου ένα "ορφανό" subdomain μπορεί να καταληφθεί.</summary>
/// <param name="Service">Η υπηρεσία.</param>
/// <param name="CnameSuffixes">Οι καταλήξεις του CNAME που δείχνουν στην υπηρεσία.</param>
/// <param name="BodyMarker">Κείμενο που εμφανίζει η υπηρεσία όταν ο πόρος δεν υπάρχει.</param>
public record TakeoverFingerprint(string Service, string[] CnameSuffixes, string BodyMarker);

/// <summary>
/// Fingerprints για την επιβεβαίωση subdomain takeover, βασισμένα στο δημόσιο έργο
/// "can-i-take-over-xyz". Μόνο υπηρεσίες όπου το takeover είναι τεκμηριωμένα εφικτό.
/// </summary>
public static class TakeoverFingerprints
{
    /// <summary>Όλα τα fingerprints.</summary>
    public static readonly IReadOnlyList<TakeoverFingerprint> All =
    [
        new("GitHub Pages", [".github.io"], "There isn't a GitHub Pages site here."),
        new("AWS S3", [".s3.amazonaws.com", ".s3-website", ".amazonaws.com"], "NoSuchBucket"),
        new("Heroku", [".herokuapp.com", ".herokudns.com", ".herokussl.com"], "No such app"),
        new("Azure App Service", [".azurewebsites.net"], "404 Web Site not found"),
        new("Azure (cloudapp)", [".cloudapp.net", ".cloudapp.azure.com", ".trafficmanager.net"], "404 Web Site not found"),
        new("Bitbucket", [".bitbucket.io"], "Repository not found"),
        new("Shopify", [".myshopify.com"], "Sorry, this shop is currently unavailable."),
        new("Fastly", [".fastly.net"], "Fastly error: unknown domain"),
        new("Surge", [".surge.sh"], "project not found"),
        new("Ghost", [".ghost.io"], "The thing you were looking for is no longer here"),
        new("Read the Docs", [".readthedocs.io"], "unknown to Read the Docs"),
        new("Pantheon", [".pantheonsite.io"], "The gods are wise, but do not know of the site which you seek."),
        new("Netlify", [".netlify.app", ".netlify.com"], "Not Found - Request ID"),
        new("Strikingly", [".s.strikinglydns.com"], "page not found"),
        new("Tumblr", ["domains.tumblr.com"], "Whatever you were looking for doesn't currently exist at this address."),
        new("WordPress.com", [".wordpress.com"], "Do you want to register"),
    ];

    /// <summary>Βρίσκει την υπηρεσία στην οποία δείχνει ένα CNAME.</summary>
    /// <param name="cname">Ο στόχος του CNAME.</param>
    /// <returns>Το fingerprint της υπηρεσίας, ή <c>null</c> αν δεν είναι γνωστή.</returns>
    public static TakeoverFingerprint? ForCname(string cname)
    {
        var name = cname.TrimEnd('.').ToLowerInvariant();
        return All.FirstOrDefault(f => f.CnameSuffixes.Any(s => name.EndsWith(s, StringComparison.Ordinal) || name.Contains(s + ".", StringComparison.Ordinal)));
    }

    /// <summary>
    /// Ελέγχει αν η σελίδα που σερβίρει η υπηρεσία δείχνει ότι ο πόρος δεν υπάρχει, δηλαδή ότι
    /// το subdomain μπορεί να καταληφθεί.
    /// </summary>
    /// <param name="fingerprint">Το fingerprint της υπηρεσίας.</param>
    /// <param name="body">Το περιεχόμενο της σελίδας.</param>
    /// <returns><c>true</c> αν το takeover είναι πιθανό.</returns>
    public static bool Matches(TakeoverFingerprint fingerprint, string body) =>
        body.Contains(fingerprint.BodyMarker, StringComparison.OrdinalIgnoreCase);
}
