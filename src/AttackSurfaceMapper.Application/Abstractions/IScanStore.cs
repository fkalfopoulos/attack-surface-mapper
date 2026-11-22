using AttackSurfaceMapper.Domain;

namespace AttackSurfaceMapper.Application.Abstractions;

/// <summary>
/// Αποθήκευση των scans, των events, των ακμών του γράφου και των logs.
/// Υλοποιείται στην Infrastructure (SQLite).
/// </summary>
public interface IScanStore
{
    /// <summary>Καταχωρεί ένα νέο scan με κατάσταση "running".</summary>
    /// <param name="target">Το domain-στόχος.</param>
    /// <param name="level">Το επίπεδο επαφής.</param>
    /// <param name="optionsJson">Οι πλήρεις ρυθμίσεις σε JSON, για αναφορά.</param>
    /// <returns>Το id του νέου scan.</returns>
    long CreateScan(string target, string level, string optionsJson);

    /// <summary>Σημειώνει ότι ένα scan τελείωσε, με την τελική του κατάσταση.</summary>
    /// <param name="scanId">Το id του scan.</param>
    /// <param name="status">finished, stopped ή failed.</param>
    /// <param name="error">Το μήνυμα σφάλματος, αν απέτυχε.</param>
    void FinishScan(long scanId, string status, string? error = null);

    /// <summary>Γράφει μια γραμμή στο log ενός scan.</summary>
    /// <param name="scanId">Το id του scan.</param>
    /// <param name="module">Το module που γράφει.</param>
    /// <param name="level">info, warn ή error.</param>
    /// <param name="message">Το μήνυμα (κόβεται στους 2000 χαρακτήρες).</param>
    void Log(long scanId, string module, string level, string message);

    /// <summary>Επιστρέφει τα πιο πρόσφατα scans, με πλήθος events και ευρημάτων.</summary>
    /// <param name="limit">Το μέγιστο πλήθος scans.</param>
    /// <returns>Τα scans, από το νεότερο στο παλαιότερο.</returns>
    List<ScanSummary> ListScans(int limit = 200);

    /// <summary>Επιστρέφει τη σύνοψη ενός scan.</summary>
    /// <param name="id">Το id του scan.</param>
    /// <returns>Η σύνοψη, ή <c>null</c> αν δεν υπάρχει.</returns>
    ScanSummary? GetScan(long id);

    /// <summary>
    /// Βρίσκει το προηγούμενο ολοκληρωμένο scan του ίδιου στόχου στο ίδιο επίπεδο, για σύγκριση.
    /// </summary>
    /// <remarks>
    /// Το επίπεδο πρέπει να είναι ίδιο: ένα footprint scan βρίσκει πολύ περισσότερα από ένα passive,
    /// και η σύγκριση θα έδειχνε ψευδώς "νέα" ή "εξαφανισμένα" δεδομένα.
    /// </remarks>
    /// <param name="scan">Το scan για το οποίο ψάχνουμε προηγούμενο.</param>
    /// <returns>Το id του προηγούμενου scan, ή <c>null</c> αν δεν υπάρχει.</returns>
    long? GetPreviousScanId(ScanSummary scan);

    /// <summary>Επιστρέφει όλα τα events ενός scan, με τη σειρά που βρέθηκαν.</summary>
    /// <param name="scanId">Το id του scan.</param>
    /// <returns>Τα events.</returns>
    List<ScanEvent> GetEvents(long scanId);

    /// <summary>Επιστρέφει όλες τις ακμές του γράφου ενός scan.</summary>
    /// <param name="scanId">Το id του scan.</param>
    /// <returns>Οι ακμές (γονέας → παιδί).</returns>
    List<Edge> GetEdges(long scanId);

    /// <summary>Επιστρέφει το log ενός scan.</summary>
    /// <param name="scanId">Το id του scan.</param>
    /// <param name="limit">Το μέγιστο πλήθος γραμμών.</param>
    /// <returns>Οι γραμμές του log, με χρονολογική σειρά.</returns>
    List<LogLine> GetLog(long scanId, int limit = 2000);

    /// <summary>Διαγράφει ένα scan μαζί με τα events, τις ακμές και το log του.</summary>
    /// <param name="id">Το id του scan.</param>
    /// <returns><c>true</c> αν βρέθηκε και διαγράφηκε.</returns>
    bool DeleteScan(long id);

    /// <summary>
    /// Αποθηκεύει ένα event, αν δεν υπάρχει ήδη στο ίδιο scan με τον ίδιο τύπο και τιμή.
    /// Αν υπάρχει, προσθέτει μόνο μια νέα ακμή από τον νέο γονέα προς το υπάρχον event.
    /// </summary>
    /// <param name="scanId">Το id του scan.</param>
    /// <param name="type">Ο τύπος του event.</param>
    /// <param name="data">Η τιμή του event.</param>
    /// <param name="module">Το module που το βρήκε.</param>
    /// <param name="parentId">Το γονικό event, ή <c>null</c> για τη ρίζα.</param>
    /// <param name="risk">Το επίπεδο κινδύνου.</param>
    /// <param name="link">Προαιρετικό link.</param>
    /// <param name="depth">Η απόσταση από τη ρίζα.</param>
    /// <returns>Το event και αν ήταν νέο. Μόνο τα νέα events στέλνονται στα modules.</returns>
    (ScanEvent Event, bool IsNew) AddEvent(long scanId, string type, string data, string module,
        long? parentId, string? risk, string? link, int depth);
}
