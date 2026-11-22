using AttackSurfaceMapper.Data;
using AttackSurfaceMapper.Engine;
using DnsClient;

namespace AttackSurfaceMapper.Tests;

/// <summary>
/// Tests για τη μηχανή των scans με ψεύτικα modules, χωρίς πρόσβαση στο δίκτυο.
/// </summary>
public sealed class ScanEngineTests : IDisposable
{
    readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"asm-test-{Guid.NewGuid():N}.db");
    readonly Store _store;

    /// <summary>Δημιουργεί καινούρια βάση σε προσωρινό αρχείο για κάθε test.</summary>
    public ScanEngineTests()
    {
        _store = new Store(_dbPath);
        _store.Init();
    }

    /// <summary>Σβήνει την προσωρινή βάση μετά από κάθε test.</summary>
    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        foreach (var f in new[] { _dbPath, _dbPath + "-wal", _dbPath + "-shm" })
            if (File.Exists(f)) File.Delete(f);
    }

    /// <summary>Ψεύτικο module που εκτελεί ό,τι του δώσει το test.</summary>
    /// <param name="name">Το όνομα.</param>
    /// <param name="watched">Οι τύποι που παρακολουθεί.</param>
    /// <param name="handle">Τι κάνει για κάθε event.</param>
    sealed class FakeModule(string name, string[] watched, Action<ScanEvent, ScanContext> handle) : IModule
    {
        /// <summary>Πόσες φορές κλήθηκε.</summary>
        public int Calls;

        /// <inheritdoc/>
        public string Name => name;
        /// <inheritdoc/>
        public string Description => "test";
        /// <inheritdoc/>
        public Footprint Level => Footprint.Passive;
        /// <inheritdoc/>
        public IReadOnlyCollection<string> Watched => watched;
        /// <inheritdoc/>
        public IReadOnlyCollection<string> Produced => [];

        /// <summary>Μετρά την κλήση και εκτελεί τη λογική του test.</summary>
        /// <param name="e">Το event.</param>
        /// <param name="ctx">Το context.</param>
        /// <param name="ct">Token ακύρωσης.</param>
        /// <returns>Ολοκληρωμένο task.</returns>
        public Task HandleAsync(ScanEvent e, ScanContext ctx, CancellationToken ct)
        {
            Interlocked.Increment(ref Calls);
            handle(e, ctx);
            return Task.CompletedTask;
        }
    }

    /// <summary>HTTP factory που αποτυγχάνει αν το χρησιμοποιήσει κάποιο module (τα tests δεν έχουν δίκτυο).</summary>
    sealed class NoHttp : IHttpClientFactory
    {
        /// <summary>Πετά πάντα exception.</summary>
        /// <param name="name">Το όνομα του client.</param>
        /// <returns>Ποτέ.</returns>
        public HttpClient CreateClient(string name) => throw new InvalidOperationException("Τα tests δεν έχουν δίκτυο.");
    }

    /// <summary>Τρέχει ένα scan για το example.com με τα modules που δίνονται.</summary>
    /// <param name="modules">Τα modules.</param>
    /// <returns>Το id του scan.</returns>
    async Task<long> RunAsync(params IModule[] modules)
    {
        var options = new ScanOptions("example.com", Footprint.Passive, [], Gitleaks: false);
        var scanId = _store.CreateScan(options.Target, "passive", "{}");
        var run = new ScanRun(scanId, options, modules, _store, new LookupClient(), new NoHttp());
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await run.RunAsync(timeout.Token);
        return scanId;
    }

    /// <summary>
    /// Ελέγχει ότι τα modules τροφοδοτούν το ένα το άλλο (domain → host → IP → ASN) και ότι το scan
    /// τελειώνει μόνο του όταν δεν υπάρχει άλλη δουλειά.
    /// </summary>
    [Fact]
    public async Task Run_ChainsModulesAndCompletes()
    {
        var subdomains = new FakeModule("subs", [EventTypes.Domain], (e, ctx) => ctx.Emit(EventTypes.Host, "api.example.com", e));
        var resolve = new FakeModule("resolve", [EventTypes.Host], (e, ctx) => ctx.Emit(EventTypes.Ip, "203.0.113.7", e));
        var asn = new FakeModule("asn", [EventTypes.Ip], (e, ctx) => ctx.Emit(EventTypes.Asn, "AS64500 · TEST", e));

        var scanId = await RunAsync(subdomains, resolve, asn);
        var events = _store.GetEvents(scanId);

        Assert.Equal([EventTypes.Domain, EventTypes.Host, EventTypes.Ip, EventTypes.Asn], events.Select(e => e.Type));
        Assert.Equal([0, 1, 2, 3], events.Select(e => e.Depth));
        Assert.Equal(events[2].Id, events[3].ParentId);
    }

    /// <summary>
    /// Ελέγχει την κανονικοποίηση και το scope: τα hostnames γίνονται πεζά, όσα είναι εκτός στόχου
    /// γίνονται AFFILIATE και δεν τα λαμβάνουν τα modules, και η ρίζα δεν διπλασιάζεται.
    /// </summary>
    [Fact]
    public async Task Run_AppliesScopeAndNormalization()
    {
        var subs = new FakeModule("subs", [EventTypes.Domain], (e, ctx) =>
        {
            ctx.Emit(EventTypes.Host, "API.Example.com.", e);
            ctx.Emit(EventTypes.Host, "cdn.other.net", e);
            ctx.Emit(EventTypes.Host, "example.com", e);    // η ίδια η ρίζα
            ctx.Emit(EventTypes.Host, "not a host", e);     // άκυρο: αγνοείται
        });
        var hostWatcher = new FakeModule("hosts", [EventTypes.Host], (_, _) => { });

        var scanId = await RunAsync(subs, hostWatcher);
        var events = _store.GetEvents(scanId);

        Assert.Single(events, e => e.Type == EventTypes.Domain);
        Assert.Contains(events, e => e is { Type: EventTypes.Host, Data: "api.example.com" });
        Assert.Contains(events, e => e is { Type: EventTypes.AffiliateHost, Data: "cdn.other.net" });
        Assert.DoesNotContain(events, e => e.Data == "not a host");
        Assert.Equal(1, hostWatcher.Calls);   // μόνο το api.example.com, όχι το affiliate
    }

    /// <summary>
    /// Ελέγχει ότι το ίδιο εύρημα από δύο πηγές αποθηκεύεται μία φορά, με δύο ακμές στον γράφο,
    /// και ότι τα modules το λαμβάνουν μόνο μία φορά.
    /// </summary>
    [Fact]
    public async Task Run_DeduplicatesEventsButKeepsEdges()
    {
        var subs = new FakeModule("subs", [EventTypes.Domain], (e, ctx) =>
        {
            ctx.Emit(EventTypes.Host, "a.example.com", e);
            ctx.Emit(EventTypes.Host, "b.example.com", e);
        });
        var resolve = new FakeModule("resolve", [EventTypes.Host], (e, ctx) => ctx.Emit(EventTypes.Ip, "203.0.113.7", e));
        var ipWatcher = new FakeModule("ip", [EventTypes.Ip], (_, _) => { });

        var scanId = await RunAsync(subs, resolve, ipWatcher);
        var ip = Assert.Single(_store.GetEvents(scanId), e => e.Type == EventTypes.Ip);

        Assert.Equal(2, _store.GetEdges(scanId).Count(x => x.To == ip.Id));
        Assert.Equal(1, ipWatcher.Calls);
    }

    /// <summary>Ελέγχει ότι ένα module που αποτυγχάνει καταγράφεται στο log χωρίς να σταματήσει το scan.</summary>
    [Fact]
    public async Task Run_LogsModuleErrorsAndContinues()
    {
        var broken = new FakeModule("broken", [EventTypes.Domain], (_, _) => throw new InvalidOperationException("boom"));
        var ok = new FakeModule("ok", [EventTypes.Domain], (e, ctx) => ctx.Emit(EventTypes.Host, "ok.example.com", e));

        var scanId = await RunAsync(broken, ok);

        Assert.Contains(_store.GetEvents(scanId), e => e.Data == "ok.example.com");
        Assert.Contains(_store.GetLog(scanId), l => l is { Module: "broken", Level: "error" } && l.Message.Contains("boom"));
    }

    /// <summary>Ελέγχει ότι η ακύρωση σταματά ένα scan που διαφορετικά δεν θα τελείωνε.</summary>
    [Fact]
    public async Task Run_StopsOnCancellation()
    {
        var slow = new SlowModule();
        var options = new ScanOptions("example.com", Footprint.Passive, [], false);
        var scanId = _store.CreateScan(options.Target, "passive", "{}");
        var run = new ScanRun(scanId, options, [slow], _store, new LookupClient(), new NoHttp());

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.RunAsync(cts.Token));
    }

    /// <summary>Module που περιμένει "για πάντα", για το test της ακύρωσης.</summary>
    sealed class SlowModule : IModule
    {
        /// <inheritdoc/>
        public string Name => "slow";
        /// <inheritdoc/>
        public string Description => "test";
        /// <inheritdoc/>
        public Footprint Level => Footprint.Passive;
        /// <inheritdoc/>
        public IReadOnlyCollection<string> Watched => [EventTypes.Domain];
        /// <inheritdoc/>
        public IReadOnlyCollection<string> Produced => [];

        /// <summary>Περιμένει μέχρι να ακυρωθεί.</summary>
        /// <param name="e">Το event.</param>
        /// <param name="ctx">Το context.</param>
        /// <param name="ct">Token ακύρωσης.</param>
        /// <returns>Task που τελειώνει μόνο με ακύρωση.</returns>
        public Task HandleAsync(ScanEvent e, ScanContext ctx, CancellationToken ct) => Task.Delay(Timeout.Infinite, ct);
    }
}
