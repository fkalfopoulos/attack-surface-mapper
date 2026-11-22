using AttackSurfaceMapper.Domain;

namespace AttackSurfaceMapper.Application.Contracts;

/// <summary>Το αίτημα για νέο scan.</summary>
/// <param name="Target">Το domain (δέχεται και URL, από το οποίο κρατά μόνο το host).</param>
/// <param name="Level">"passive" ή "footprint".</param>
/// <param name="Modules">Τα modules που θα τρέξουν· κενό σημαίνει όλα του επιπέδου.</param>
/// <param name="Gitleaks">Αν τα repos θα σκαναριστούν με το Gitleaks Scanner.</param>
/// <param name="Authorized">Επιβεβαίωση του χρήστη ότι έχει άδεια για footprint scan.</param>
public record StartScanRequest(string? Target, string? Level, string[]? Modules, bool Gitleaks, bool Authorized);

/// <summary>Περιγραφή ενός module για το UI.</summary>
/// <param name="Name">Το όνομα.</param>
/// <param name="Description">Η περιγραφή.</param>
/// <param name="Level">"passive" ή "footprint".</param>
/// <param name="Watched">Οι τύποι που παρακολουθεί.</param>
/// <param name="Produced">Οι τύποι που παράγει.</param>
public record ModuleInfo(string Name, string Description, string Level, IReadOnlyCollection<string> Watched,
    IReadOnlyCollection<string> Produced);

/// <summary>Ένα scan στη λίστα του ιστορικού.</summary>
/// <param name="Scan">Η σύνοψη.</param>
/// <param name="Running">Αν τρέχει αυτή τη στιγμή.</param>
public record ScanListItem(ScanSummary Scan, bool Running);

/// <summary>Η σύνοψη ενός scan με πλήθος events ανά τύπο.</summary>
/// <param name="Scan">Η σύνοψη.</param>
/// <param name="Running">Αν τρέχει.</param>
/// <param name="Counts">Πλήθος events ανά τύπο.</param>
public record ScanDetails(ScanSummary Scan, bool Running, Dictionary<string, int> Counts);

/// <summary>Ο γράφος ενός scan, η σύγκριση με το προηγούμενο και οι συσχετίσεις.</summary>
/// <param name="Events">Οι κόμβοι.</param>
/// <param name="Edges">Οι ακμές.</param>
/// <param name="Diff">Η σύγκριση με το προηγούμενο scan.</param>
/// <param name="Correlations">Τα ευρήματα των κανόνων συσχέτισης.</param>
public record ScanGraph(List<ScanEvent> Events, List<Edge> Edges, ScanDiff Diff, List<Correlation> Correlations);

/// <summary>Η κατάσταση του Gitleaks Scanner.</summary>
/// <param name="Available">Αν απαντά.</param>
/// <param name="Url">Η διεύθυνσή του.</param>
public record GitleaksHealth(bool Available, Uri? Url);

/// <summary>Το αποτέλεσμα ενός scan στο Gitleaks Scanner.</summary>
/// <param name="ScanId">Το id του scan εκεί.</param>
/// <param name="Total">Πόσα secrets βρέθηκαν.</param>
/// <param name="Link">Link προς τη σελίδα του scan.</param>
public record GitleaksScanResult(long ScanId, int Total, string Link);
