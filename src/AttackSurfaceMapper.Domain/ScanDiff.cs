namespace AttackSurfaceMapper.Domain;

/// <summary>
/// Η σύγκριση ενός scan με το προηγούμενο του ίδιου στόχου.
/// </summary>
/// <param name="PreviousScanId">Το scan με το οποίο έγινε η σύγκριση, ή <c>null</c> αν είναι το πρώτο.</param>
/// <param name="NewIds">Τα ids των events που δεν υπήρχαν στο προηγούμενο scan.</param>
/// <param name="Removed">
/// Τα events του προηγούμενου scan που δεν βρέθηκαν τώρα, ή <c>null</c> όσο το scan τρέχει
/// (θα έδειχνε ως "εξαφανισμένα" όσα απλώς δεν έχουν βρεθεί ακόμα).
/// </param>
public record ScanDiff(long? PreviousScanId, IReadOnlyList<long> NewIds, IReadOnlyList<ScanEvent>? Removed)
{
    /// <summary>
    /// Υπολογίζει ποια events είναι νέα και ποια εξαφανίστηκαν ανάμεσα σε δύο λίστες.
    /// </summary>
    /// <param name="previousScanId">Το id του προηγούμενου scan.</param>
    /// <param name="previous">Τα events του προηγούμενου scan.</param>
    /// <param name="current">Τα events του τρέχοντος scan.</param>
    /// <param name="running">Αν το τρέχον scan δεν έχει τελειώσει.</param>
    /// <returns>Η σύγκριση.</returns>
    public static ScanDiff Compare(long previousScanId, IReadOnlyList<ScanEvent> previous,
        IReadOnlyList<ScanEvent> current, bool running)
    {
        var prevKeys = previous.Select(Key).ToHashSet();
        var currKeys = current.Select(Key).ToHashSet();

        // Η ρίζα (το domain) υπάρχει πάντα και στα δύο· δεν έχει νόημα να φαίνεται ως "νέα".
        var newIds = current.Where(e => e.ParentId is not null && !prevKeys.Contains(Key(e))).Select(e => e.Id).ToList();
        var removed = running ? null : previous.Where(e => !currKeys.Contains(Key(e))).ToList();
        return new ScanDiff(previousScanId, newIds, removed);
    }

    /// <summary>Το κλειδί σύγκρισης ενός event: τύπος και τιμή.</summary>
    /// <param name="e">Το event.</param>
    /// <returns>Ένα κλειδί, μοναδικό ανά (τύπο, τιμή).</returns>
    static (string, string) Key(ScanEvent e) => (e.Type, e.Data);
}
