using AttackSurfaceMapper.Application.Abstractions;
using AttackSurfaceMapper.Domain;
using Microsoft.Data.Sqlite;

namespace AttackSurfaceMapper.Infrastructure.Persistence;

/// <summary>
/// Αποθήκευση των scans, των events, των ακμών του γράφου και των logs σε SQLite.
/// </summary>
/// <remarks>
/// Πολλά modules γράφουν ταυτόχρονα. Η SQLite δέχεται έναν writer τη φορά, γι' αυτό οι
/// εγγραφές περνούν από ένα κοινό lock αντί να περιμένουν η μία την άλλη με busy_timeout.
/// </remarks>
public sealed class SqliteScanStore : IScanStore
{
    readonly string _cs;
    readonly Lock _writeLock = new();

    /// <summary>Δημιουργεί το store για το αρχείο βάσης που δίνεται.</summary>
    /// <param name="dbPath">Η διαδρομή του αρχείου SQLite.</param>
    public SqliteScanStore(string dbPath) =>
        _cs = new SqliteConnectionStringBuilder { DataSource = dbPath }.ToString();

    /// <summary>Ανοίγει νέα σύνδεση με ενεργά foreign keys.</summary>
    /// <returns>Μια ανοιχτή σύνδεση. Ο caller την κλείνει με <c>using</c>.</returns>
    SqliteConnection Open()
    {
        var c = new SqliteConnection(_cs);
        c.Open();
        Exec(c, "PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
        return c;
    }

    /// <summary>Φτιάχνει SQL εντολή με παραμέτρους (ποτέ με string concatenation, για αποφυγή SQL injection).</summary>
    /// <param name="c">Η σύνδεση.</param>
    /// <param name="sql">Το SQL, με παραμέτρους της μορφής <c>$όνομα</c>.</param>
    /// <param name="ps">Ζεύγη (όνομα, τιμή) για τις παραμέτρους.</param>
    /// <returns>Η εντολή, έτοιμη για εκτέλεση.</returns>
    static SqliteCommand Cmd(SqliteConnection c, string sql, params (string, object?)[] ps)
    {
        var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        foreach (var (n, v) in ps) cmd.Parameters.AddWithValue(n, v ?? DBNull.Value);
        return cmd;
    }

    /// <summary>Εκτελεί μια SQL εντολή που δεν επιστρέφει δεδομένα.</summary>
    /// <param name="c">Η σύνδεση.</param>
    /// <param name="sql">Το SQL.</param>
    /// <param name="ps">Οι παράμετροι.</param>
    static void Exec(SqliteConnection c, string sql, params (string, object?)[] ps)
    {
        using var cmd = Cmd(c, sql, ps);
        cmd.ExecuteNonQuery();
    }

    /// <summary>Επιστρέφει την τρέχουσα ώρα σε UTC, σε μορφή ISO 8601.</summary>
    static string Now() => DateTime.UtcNow.ToString("O");

    /// <summary>
    /// Δημιουργεί τους πίνακες αν δεν υπάρχουν και σημειώνει ως "interrupted" όσα scans
    /// έτρεχαν όταν σταμάτησε απότομα το app.
    /// </summary>
    public void Init()
    {
        using var c = Open();
        Exec(c, "PRAGMA journal_mode = WAL;");
        Exec(c, """
            CREATE TABLE IF NOT EXISTS scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                target      TEXT NOT NULL,
                level       TEXT NOT NULL,
                options     TEXT NOT NULL,
                status      TEXT NOT NULL,
                started_at  TEXT NOT NULL,
                finished_at TEXT,
                error       TEXT
            );

            CREATE TABLE IF NOT EXISTS events (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id    INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                type       TEXT NOT NULL,
                data       TEXT NOT NULL,
                module     TEXT NOT NULL,
                parent_id  INTEGER,
                risk       TEXT,
                link       TEXT,
                depth      INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                -- Το ίδιο εύρημα αποθηκεύεται μία φορά ανά scan· οι επιπλέον "γονείς" του
                -- γίνονται ακμές στον πίνακα edges.
                UNIQUE (scan_id, type, data)
            );
            CREATE INDEX IF NOT EXISTS idx_events_scan ON events(scan_id, id);

            CREATE TABLE IF NOT EXISTS edges (
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                from_id INTEGER NOT NULL,
                to_id   INTEGER NOT NULL,
                PRIMARY KEY (scan_id, from_id, to_id)
            );

            CREATE TABLE IF NOT EXISTS scan_log (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                at      TEXT NOT NULL,
                module  TEXT NOT NULL,
                level   TEXT NOT NULL,
                message TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_log_scan ON scan_log(scan_id, id);
            """);
        Exec(c, "UPDATE scans SET status = 'interrupted', finished_at = $t WHERE status = 'running'", ("$t", Now()));
    }

    /// <inheritdoc/>
    public long CreateScan(string target, string level, string optionsJson)
    {
        lock (_writeLock)
        {
            using var c = Open();
            using var cmd = Cmd(c, """
                INSERT INTO scans (target, level, options, status, started_at)
                VALUES ($t, $l, $o, 'running', $s) RETURNING id
                """, ("$t", target), ("$l", level), ("$o", optionsJson), ("$s", Now()));
            return (long)cmd.ExecuteScalar()!;
        }
    }

    /// <inheritdoc/>
    public void FinishScan(long scanId, string status, string? error = null)
    {
        lock (_writeLock)
        {
            using var c = Open();
            Exec(c, "UPDATE scans SET status = $s, finished_at = $t, error = $e WHERE id = $id",
                ("$s", status), ("$t", Now()), ("$e", error), ("$id", scanId));
        }
    }

    /// <inheritdoc/>
    public (ScanEvent Event, bool IsNew) AddEvent(long scanId, string type, string data, string module,
        long? parentId, string? risk, string? link, int depth)
    {
        lock (_writeLock)
        {
            using var c = Open();
            using var tx = c.BeginTransaction();

            using var ins = Cmd(c, """
                INSERT INTO events (scan_id, type, data, module, parent_id, risk, link, depth, created_at)
                VALUES ($s, $t, $d, $m, $p, $r, $l, $dp, $c)
                ON CONFLICT (scan_id, type, data) DO NOTHING
                RETURNING id
                """, ("$s", scanId), ("$t", type), ("$d", data), ("$m", module), ("$p", parentId),
                ("$r", risk), ("$l", link), ("$dp", depth), ("$c", Now()));
            ins.Transaction = tx;
            var newId = ins.ExecuteScalar();

            ScanEvent ev;
            bool isNew = newId is long;
            if (isNew)
            {
                ev = new ScanEvent((long)newId!, type, data, module, parentId, risk, link, depth);
            }
            else
            {
                using var sel = Cmd(c, "SELECT id, module, parent_id, risk, link, depth FROM events WHERE scan_id = $s AND type = $t AND data = $d",
                    ("$s", scanId), ("$t", type), ("$d", data));
                sel.Transaction = tx;
                using var r = sel.ExecuteReader();
                r.Read();
                ev = new ScanEvent(r.GetInt64(0), type, data, r.GetString(1), r.IsDBNull(2) ? null : r.GetInt64(2),
                    r.IsDBNull(3) ? null : r.GetString(3), r.IsDBNull(4) ? null : r.GetString(4), r.GetInt32(5));
            }

            if (parentId is long p && p != ev.Id)
            {
                using var edge = Cmd(c, "INSERT OR IGNORE INTO edges (scan_id, from_id, to_id) VALUES ($s, $f, $t)",
                    ("$s", scanId), ("$f", p), ("$t", ev.Id));
                edge.Transaction = tx;
                edge.ExecuteNonQuery();
            }
            tx.Commit();
            return (ev, isNew);
        }
    }

    /// <inheritdoc/>
    public void Log(long scanId, string module, string level, string message)
    {
        if (message.Length > 2000) message = message[..2000];
        lock (_writeLock)
        {
            using var c = Open();
            Exec(c, "INSERT INTO scan_log (scan_id, at, module, level, message) VALUES ($s, $a, $m, $l, $msg)",
                ("$s", scanId), ("$a", Now()), ("$m", module), ("$l", level), ("$msg", message));
        }
    }

    /// <inheritdoc/>
    public List<ScanSummary> ListScans(int limit = 200)
    {
        using var c = Open();
        using var cmd = Cmd(c, SummarySql + " ORDER BY s.id DESC LIMIT $l", ("$l", limit));
        return ReadSummaries(cmd);
    }

    /// <inheritdoc/>
    public ScanSummary? GetScan(long id)
    {
        using var c = Open();
        using var cmd = Cmd(c, SummarySql + " WHERE s.id = $id", ("$id", id));
        return ReadSummaries(cmd).FirstOrDefault();
    }

    const string SummarySql = """
        SELECT s.id, s.target, s.level, s.status, s.started_at, s.finished_at, s.error,
               (SELECT COUNT(*) FROM events e WHERE e.scan_id = s.id),
               (SELECT COUNT(*) FROM events e WHERE e.scan_id = s.id AND e.risk IN ('low','medium','high'))
        FROM scans s
        """;

    /// <summary>Διαβάζει τις γραμμές του <see cref="SummarySql"/> σε αντικείμενα <see cref="ScanSummary"/>.</summary>
    /// <param name="cmd">Η εντολή που θα εκτελεστεί.</param>
    /// <returns>Οι συνόψεις.</returns>
    static List<ScanSummary> ReadSummaries(SqliteCommand cmd)
    {
        using var r = cmd.ExecuteReader();
        var list = new List<ScanSummary>();
        while (r.Read())
            list.Add(new ScanSummary(r.GetInt64(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetString(4),
                r.IsDBNull(5) ? null : r.GetString(5), r.GetInt32(7), r.GetInt32(8), r.IsDBNull(6) ? null : r.GetString(6)));
        return list;
    }

    /// <inheritdoc/>
    public long? GetPreviousScanId(ScanSummary scan)
    {
        using var c = Open();
        using var cmd = Cmd(c, """
            SELECT id FROM scans
            WHERE target = $t AND level = $l AND status = 'finished' AND id < $id
            ORDER BY id DESC LIMIT 1
            """, ("$t", scan.Target), ("$l", scan.Level), ("$id", scan.Id));
        return cmd.ExecuteScalar() is long v ? v : null;
    }

    /// <inheritdoc/>
    public List<ScanEvent> GetEvents(long scanId)
    {
        using var c = Open();
        using var cmd = Cmd(c, "SELECT id, type, data, module, parent_id, risk, link, depth FROM events WHERE scan_id = $s ORDER BY id",
            ("$s", scanId));
        using var r = cmd.ExecuteReader();
        var list = new List<ScanEvent>();
        while (r.Read())
            list.Add(new ScanEvent(r.GetInt64(0), r.GetString(1), r.GetString(2), r.GetString(3),
                r.IsDBNull(4) ? null : r.GetInt64(4), r.IsDBNull(5) ? null : r.GetString(5),
                r.IsDBNull(6) ? null : r.GetString(6), r.GetInt32(7)));
        return list;
    }

    /// <inheritdoc/>
    public List<Edge> GetEdges(long scanId)
    {
        using var c = Open();
        using var cmd = Cmd(c, "SELECT from_id, to_id FROM edges WHERE scan_id = $s", ("$s", scanId));
        using var r = cmd.ExecuteReader();
        var list = new List<Edge>();
        while (r.Read()) list.Add(new Edge(r.GetInt64(0), r.GetInt64(1)));
        return list;
    }

    /// <inheritdoc/>
    public List<LogLine> GetLog(long scanId, int limit = 2000)
    {
        using var c = Open();
        using var cmd = Cmd(c, "SELECT at, module, level, message FROM scan_log WHERE scan_id = $s ORDER BY id LIMIT $l",
            ("$s", scanId), ("$l", limit));
        using var r = cmd.ExecuteReader();
        var list = new List<LogLine>();
        while (r.Read()) list.Add(new LogLine(r.GetString(0), r.GetString(1), r.GetString(2), r.GetString(3)));
        return list;
    }

    /// <inheritdoc/>
    public bool DeleteScan(long id)
    {
        lock (_writeLock)
        {
            using var c = Open();
            using var cmd = Cmd(c, "DELETE FROM scans WHERE id = $id", ("$id", id));
            return cmd.ExecuteNonQuery() > 0;
        }
    }
}
