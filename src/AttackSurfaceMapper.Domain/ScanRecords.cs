namespace AttackSurfaceMapper.Domain;

/// <summary>Σύνοψη ενός scan για τη λίστα και τη σελίδα του scan.</summary>
/// <param name="Id">Το id του scan.</param>
/// <param name="Target">Το domain-στόχος.</param>
/// <param name="Level">Το επίπεδο επαφής (passive / footprint).</param>
/// <param name="Status">running, finished, stopped, failed ή interrupted.</param>
/// <param name="StartedAt">Πότε ξεκίνησε (ISO 8601, UTC).</param>
/// <param name="FinishedAt">Πότε τελείωσε, ή <c>null</c> αν τρέχει ακόμα.</param>
/// <param name="EventCount">Πόσα events βρέθηκαν.</param>
/// <param name="IssueCount">Πόσα events έχουν επίπεδο κινδύνου low ή υψηλότερο.</param>
/// <param name="Error">Μήνυμα σφάλματος αν απέτυχε.</param>
public record ScanSummary(long Id, string Target, string Level, string Status, string StartedAt,
    string? FinishedAt, int EventCount, int IssueCount, string? Error);

/// <summary>Μια γραμμή του log ενός scan.</summary>
/// <param name="At">Πότε γράφτηκε (ISO 8601, UTC).</param>
/// <param name="Module">Το module που την έγραψε.</param>
/// <param name="Level">info, warn ή error.</param>
/// <param name="Message">Το μήνυμα.</param>
public record LogLine(string At, string Module, string Level, string Message);

/// <summary>Μια ακμή του γράφου: το event <paramref name="From"/> οδήγησε στο <paramref name="To"/>.</summary>
/// <param name="From">Το id του γονικού event.</param>
/// <param name="To">Το id του event που προέκυψε.</param>
public record Edge(long From, long To);
