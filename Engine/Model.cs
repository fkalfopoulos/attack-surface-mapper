namespace AttackSurfaceMapper.Engine;

/// <summary>
/// Ένα κομμάτι πληροφορίας που βρέθηκε κατά το scan (ένας κόμβος του γράφου).
/// </summary>
/// <param name="Id">Το μοναδικό id του event στη βάση.</param>
/// <param name="Type">Ο τύπος του event (βλ. <see cref="EventTypes"/>).</param>
/// <param name="Data">Η τιμή, π.χ. ένα hostname ή μια IP.</param>
/// <param name="Module">Το module που το βρήκε.</param>
/// <param name="ParentId">Το event από το οποίο προέκυψε, ή <c>null</c> για τη ρίζα.</param>
/// <param name="Risk">Επίπεδο κινδύνου (info, low, medium, high), ή <c>null</c> αν είναι απλή πληροφορία.</param>
/// <param name="Link">Προαιρετικό link για λεπτομέρειες (π.χ. προς το Gitleaks Scanner).</param>
/// <param name="Depth">Πόσα βήματα απέχει από τη ρίζα.</param>
public sealed record ScanEvent(long Id, string Type, string Data, string Module, long? ParentId,
    string? Risk, string? Link, int Depth);

/// <summary>
/// Πόσο "αγγίζει" ένα module τον στόχο.
/// </summary>
public enum Footprint
{
    /// <summary>Μόνο πηγές τρίτων (DNS resolvers, crt.sh, RDAP, RIPEstat, GitHub). Ο στόχος δεν βλέπει τίποτα.</summary>
    Passive = 0,
    /// <summary>Κανονική επίσκεψη όπως ενός browser (HTTPS/TLS). Φαίνεται στα logs του στόχου.</summary>
    Footprint = 1,
    /// <summary>Επιθετικές τεχνικές (brute force, port scan). Φάση 3, μόνο με ρητή άδεια.</summary>
    Active = 2,
}

/// <summary>
/// Ένα module συλλογής πληροφοριών. Παρακολουθεί ορισμένους τύπους events και παράγει νέους.
/// </summary>
public interface IModule
{
    /// <summary>Το μοναδικό όνομα του module (π.χ. "dns_resolve").</summary>
    string Name { get; }

    /// <summary>Σύντομη ελληνική περιγραφή του τι κάνει το module.</summary>
    string Description { get; }

    /// <summary>Πόσο αγγίζει τον στόχο. Τα modules πάνω από το επίπεδο του scan δεν τρέχουν.</summary>
    Footprint Level { get; }

    /// <summary>Οι τύποι events που θέλει να λαμβάνει το module.</summary>
    IReadOnlyCollection<string> Watched { get; }

    /// <summary>Οι τύποι events που μπορεί να παράγει (για το UI και την τεκμηρίωση).</summary>
    IReadOnlyCollection<string> Produced { get; }

    /// <summary>
    /// Επεξεργάζεται ένα event και παράγει νέα events μέσω του <paramref name="ctx"/>.
    /// </summary>
    /// <param name="e">Το event που πρέπει να επεξεργαστεί.</param>
    /// <param name="ctx">Το context του scan, για εκπομπή νέων events, logging και HTTP clients.</param>
    /// <param name="ct">Ακυρώνεται όταν σταματήσει το scan.</param>
    /// <returns>Ένα task που ολοκληρώνεται όταν τελειώσει η επεξεργασία.</returns>
    Task HandleAsync(ScanEvent e, ScanContext ctx, CancellationToken ct);
}

/// <summary>
/// Οι ρυθμίσεις ενός scan.
/// </summary>
/// <param name="Target">Το domain-στόχος, κανονικοποιημένο.</param>
/// <param name="Level">Το μέγιστο επίπεδο επαφής με τον στόχο.</param>
/// <param name="Modules">Τα ονόματα των modules που επέλεξε ο χρήστης.</param>
/// <param name="Gitleaks">Αν τα repos που βρίσκονται θα σκανάρονται με το Gitleaks Scanner.</param>
public record ScanOptions(string Target, Footprint Level, IReadOnlyCollection<string> Modules, bool Gitleaks);
