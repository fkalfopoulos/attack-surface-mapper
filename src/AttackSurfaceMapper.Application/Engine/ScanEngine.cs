using System.Collections.Concurrent;
using System.Text.Json;
using System.Threading.Channels;
using AttackSurfaceMapper.Application.Abstractions;
using AttackSurfaceMapper.Domain;
using Microsoft.Extensions.Logging;

namespace AttackSurfaceMapper.Application.Engine;

/// <summary>
/// Ό,τι χρειάζεται ένα module όσο επεξεργάζεται ένα event: εκπομπή νέων events και log.
/// Δημιουργείται ένα για κάθε κλήση module. Τα DNS/HTTP τα παίρνουν τα modules με dependency injection.
/// </summary>
public sealed class ScanContext
{
    readonly ScanRun _run;
    readonly string _module;

    /// <summary>Δημιουργεί context για ένα module μέσα σε ένα scan που τρέχει.</summary>
    /// <param name="run">Το scan που τρέχει.</param>
    /// <param name="module">Το όνομα του module που θα χρησιμοποιήσει το context.</param>
    internal ScanContext(ScanRun run, string module)
    {
        _run = run;
        _module = module;
    }

    /// <summary>Το domain-στόχος του scan.</summary>
    public string Target => _run.Options.Target;

    /// <summary>Οι ρυθμίσεις του scan.</summary>
    public ScanOptions Options => _run.Options;

    /// <summary>
    /// Εκπέμπει ένα νέο εύρημα. Αν είναι νέο για αυτό το scan, θα το λάβουν όσα modules το παρακολουθούν.
    /// </summary>
    /// <param name="type">Ο τύπος (βλ. <see cref="EventTypes"/>).</param>
    /// <param name="data">Η τιμή. Αν είναι κενή ή άκυρη, το εύρημα αγνοείται.</param>
    /// <param name="parent">Το event από το οποίο προέκυψε.</param>
    /// <param name="risk">Προαιρετικό επίπεδο κινδύνου (info, low, medium, high).</param>
    /// <param name="link">Προαιρετικό link για λεπτομέρειες.</param>
    /// <returns>
    /// Το event (νέο ή υπάρχον με την ίδια τιμή), για να χρησιμοποιηθεί ως γονέας άλλων events.
    /// <c>null</c> αν η τιμή ήταν άκυρη ή έφτασε το όριο events.
    /// </returns>
    public ScanEvent? Emit(string type, string? data, ScanEvent parent, string? risk = null, string? link = null) =>
        _run.Emit(_module, type, data, parent, risk, link);

    /// <summary>Γράφει μήνυμα στο log του scan, που φαίνεται στην καρτέλα "Log" του UI.</summary>
    /// <param name="message">Το μήνυμα.</param>
    /// <param name="level">info, warn ή error.</param>
    public void Log(string message, string level = "info") => _run.Log(_module, level, message);
}

/// <summary>
/// Ένα scan που τρέχει: η ουρά των events, η διανομή τους στα modules και τα όρια ασφαλείας.
/// </summary>
/// <remarks>
/// Η μηχανή μετρά πόση δουλειά εκκρεμεί (<see cref="_pending"/>): +1 για κάθε νέο event και
/// για κάθε κλήση module, −1 όταν τελειώσει. Όταν φτάσει στο 0, δεν υπάρχει τίποτα άλλο να
/// γίνει και το scan ολοκληρώνεται. Επειδή ένα module εκπέμπει τα νέα events ΠΡΙΝ τελειώσει,
/// ο μετρητής δεν μηδενίζεται ποτέ πρόωρα.
/// </remarks>
internal sealed class ScanRun
{
    /// <summary>Μέγιστο πλήθος events ανά scan, για να μη "φουσκώσει" ένα scan επ' αόριστον.</summary>
    const int MaxEvents = 5000;

    /// <summary>Πόσα modules τρέχουν ταυτόχρονα.</summary>
    const int Concurrency = 12;

    readonly Channel<ScanEvent> _queue = Channel.CreateUnbounded<ScanEvent>();
    readonly SemaphoreSlim _slots = new(Concurrency);
    readonly ConcurrentDictionary<string, int> _touched = new();
    readonly IReadOnlyList<IModule> _modules;
    readonly IScanStore _store;
    readonly ILogger _logger;
    int _pending;
    int _eventCount;
    int _limitLogged;

    /// <summary>Το id του scan στη βάση.</summary>
    public long ScanId { get; }

    /// <summary>Οι ρυθμίσεις του scan.</summary>
    public ScanOptions Options { get; }

    /// <summary>Προετοιμάζει ένα scan. Δεν ξεκινά μέχρι να κληθεί η <see cref="RunAsync"/>.</summary>
    /// <param name="scanId">Το id του scan στη βάση.</param>
    /// <param name="options">Οι ρυθμίσεις.</param>
    /// <param name="modules">Τα modules που θα τρέξουν (ήδη φιλτραρισμένα ανά επίπεδο και επιλογή).</param>
    /// <param name="store">Η βάση.</param>
    /// <param name="logger">Ο logger της εφαρμογής (τα warnings/errors των modules γράφονται και εκεί).</param>
    public ScanRun(long scanId, ScanOptions options, IReadOnlyList<IModule> modules, IScanStore store, ILogger logger)
    {
        ScanId = scanId;
        Options = options;
        _modules = modules;
        _store = store;
        _logger = logger;
    }

    /// <summary>
    /// Τρέχει το scan μέχρι να μην υπάρχει άλλη δουλειά ή να ακυρωθεί.
    /// </summary>
    /// <param name="ct">Ακυρώνεται όταν ο χρήστης πατήσει "Stop".</param>
    /// <returns>Ένα task που ολοκληρώνεται όταν τελειώσει το scan.</returns>
    /// <exception cref="OperationCanceledException">Αν το scan σταμάτησε από τον χρήστη.</exception>
    public async Task RunAsync(CancellationToken ct)
    {
        Log("engine", "info", $"Έναρξη scan για {Options.Target} ({Options.Level}) με {_modules.Count} modules: " +
            string.Join(", ", _modules.Select(m => m.Name)));

        Emit("engine", EventTypes.Domain, Options.Target, parent: null, risk: null, link: null);

        await foreach (var ev in _queue.Reader.ReadAllAsync(ct))
        {
            foreach (var module in _modules)
            {
                if (!module.Watched.Contains(ev.Type)) continue;
                if (module.Level >= Footprint.Footprint && !TryTouch(module)) continue;
                Interlocked.Increment(ref _pending);
                _ = RunModuleAsync(module, ev, ct);
            }
            Done();
        }
        ct.ThrowIfCancellationRequested();
        Log("engine", "info", $"Ολοκληρώθηκε: {_eventCount} events.");
    }

    /// <summary>
    /// Ελέγχει αν ένα footprint module έχει ακόμα "όριο" να συνδεθεί σε άλλον host.
    /// </summary>
    /// <param name="module">Το module.</param>
    /// <returns><c>true</c> αν επιτρέπεται να τρέξει άλλη μία φορά.</returns>
    bool TryTouch(IModule module)
    {
        var n = _touched.AddOrUpdate(module.Name, 1, (_, v) => v + 1);
        if (n == module.MaxTargets + 1)
            Log(module.Name, "warn", $"Έφτασε το όριο των {module.MaxTargets} στόχων· οι υπόλοιποι παραλείπονται.");
        return n <= module.MaxTargets;
    }

    /// <summary>
    /// Τρέχει ένα module για ένα event, μέσα στο όριο ταυτόχρονων εκτελέσεων. Τα σφάλματα
    /// καταγράφονται στο log και δεν σταματούν το υπόλοιπο scan.
    /// </summary>
    /// <param name="module">Το module.</param>
    /// <param name="ev">Το event που θα επεξεργαστεί.</param>
    /// <param name="ct">Token ακύρωσης του scan.</param>
    async Task RunModuleAsync(IModule module, ScanEvent ev, CancellationToken ct)
    {
        try
        {
            await _slots.WaitAsync(ct);
            try
            {
                await module.HandleAsync(ev, new ScanContext(this, module.Name), ct);
            }
            finally
            {
                _slots.Release();
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Το scan σταμάτησε από τον χρήστη.
        }
        catch (Exception ex)
        {
            Log(module.Name, "error", $"{ev.Data}: {ex.GetType().Name}: {ex.Message}");
        }
        finally
        {
            Done();
        }
    }

    /// <summary>Σημειώνει ότι τελείωσε μια μονάδα δουλειάς· αν δεν μένει καμία, κλείνει την ουρά.</summary>
    void Done()
    {
        if (Interlocked.Decrement(ref _pending) == 0) _queue.Writer.TryComplete();
    }

    /// <summary>
    /// Κανονικοποιεί και αποθηκεύει ένα εύρημα. Αν είναι νέο, το βάζει στην ουρά για τα modules.
    /// </summary>
    /// <param name="module">Το module που το βρήκε.</param>
    /// <param name="type">Ο τύπος του.</param>
    /// <param name="data">Η τιμή του.</param>
    /// <param name="parent">Το γονικό event, ή <c>null</c> για τη ρίζα.</param>
    /// <param name="risk">Το επίπεδο κινδύνου.</param>
    /// <param name="link">Προαιρετικό link.</param>
    /// <returns>Το event (νέο ή υπάρχον), ή <c>null</c> αν αγνοήθηκε.</returns>
    public ScanEvent? Emit(string module, string type, string? data, ScanEvent? parent, string? risk, string? link)
    {
        (type, data) = Normalize(type, data);
        if (data is null) return null;

        if (Volatile.Read(ref _eventCount) >= MaxEvents)
        {
            if (Interlocked.Exchange(ref _limitLogged, 1) == 0)
                Log("engine", "warn", $"Έφτασε το όριο των {MaxEvents} events· τα επόμενα αγνοούνται.");
            return null;
        }

        var (ev, isNew) = _store.AddEvent(ScanId, type, data, module, parent?.Id, risk, link, (parent?.Depth ?? -1) + 1);
        if (!isNew) return ev;

        Interlocked.Increment(ref _eventCount);
        Interlocked.Increment(ref _pending);
        if (!_queue.Writer.TryWrite(ev)) Interlocked.Decrement(ref _pending);   // το scan έχει ήδη κλείσει
        return ev;
    }

    /// <summary>
    /// Κανονικοποιεί την τιμή ενός ευρήματος και, για τα hostnames, αποφασίζει αν είναι
    /// μέσα στο scope (INTERNET_NAME) ή εκτός (AFFILIATE_INTERNET_NAME).
    /// </summary>
    /// <param name="type">Ο τύπος όπως τον έδωσε το module.</param>
    /// <param name="data">Η τιμή όπως την έδωσε το module.</param>
    /// <returns>Ο τελικός τύπος και η κανονικοποιημένη τιμή, ή τιμή <c>null</c> αν το εύρημα είναι άκυρο.</returns>
    (string Type, string? Data) Normalize(string type, string? data)
    {
        if (string.IsNullOrWhiteSpace(data)) return (type, null);
        data = data.Trim();
        if (data.Length > 2000) data = data[..2000];

        switch (type)
        {
            case EventTypes.Domain:
            case EventTypes.Host:
            case EventTypes.AffiliateHost:
            case EventTypes.HostUnresolved:
                var host = Scope.NormalizeHost(data);
                if (host is null) return (type, null);
                if (type == EventTypes.Domain || type == EventTypes.HostUnresolved) return (type, host);
                // Αν ένα module ξαναβρεί το ίδιο το domain (π.χ. στο certificate), είναι η ρίζα και
                // όχι νέο hostname· αλλιώς θα εμφανιζόταν δύο φορές στον γράφο.
                if (host == Options.Target) return (EventTypes.Domain, host);
                return (Scope.InScope(host, Options.Target) ? EventTypes.Host : EventTypes.AffiliateHost, host);
            case EventTypes.Email:
                return (type, data.ToLowerInvariant());
            default:
                return (type, data);
        }
    }

    /// <summary>
    /// Γράφει στο log του scan (που φαίνεται στο UI). Τα warnings και τα errors γράφονται και στο
    /// log της εφαρμογής, με το id του scan και το module, για διάγνωση προβλημάτων.
    /// </summary>
    /// <param name="module">Το module.</param>
    /// <param name="level">info, warn ή error.</param>
    /// <param name="message">Το μήνυμα.</param>
    public void Log(string module, string level, string message)
    {
        _store.Log(ScanId, module, level, message);
        var logLevel = level switch { "error" => LogLevel.Error, "warn" => LogLevel.Warning, _ => LogLevel.Debug };
        _logger.Log(logLevel, "Scan #{ScanId} [{Module}] {Message}", ScanId, module, message);
    }
}

/// <summary>
/// Ξεκινά, παρακολουθεί και σταματά τα scans στο background.
/// </summary>
public sealed class ScanManager
{
    /// <summary>Πόσα scans μπορούν να τρέχουν ταυτόχρονα.</summary>
    public const int MaxConcurrentScans = 3;

    readonly ConcurrentDictionary<long, CancellationTokenSource> _running = new();
    readonly IEnumerable<IModule> _allModules;
    readonly IScanStore _store;
    readonly ILogger<ScanManager> _logger;

    /// <summary>Δημιουργεί τον manager (μέσω dependency injection).</summary>
    /// <param name="modules">Όλα τα διαθέσιμα modules.</param>
    /// <param name="store">Η βάση.</param>
    /// <param name="logger">Ο logger της εφαρμογής.</param>
    public ScanManager(IEnumerable<IModule> modules, IScanStore store, ILogger<ScanManager> logger)
    {
        _allModules = modules;
        _store = store;
        _logger = logger;
    }

    /// <summary>Όλα τα διαθέσιμα modules, για το UI.</summary>
    public IEnumerable<IModule> Modules => _allModules;

    /// <summary>Ελέγχει αν ένα scan τρέχει αυτή τη στιγμή.</summary>
    /// <param name="scanId">Το id του scan.</param>
    /// <returns><c>true</c> αν τρέχει.</returns>
    public bool IsRunning(long scanId) => _running.ContainsKey(scanId);

    /// <summary>
    /// Ξεκινά νέο scan στο background και επιστρέφει αμέσως.
    /// </summary>
    /// <param name="options">Οι ρυθμίσεις του scan.</param>
    /// <returns>Το id του νέου scan.</returns>
    /// <exception cref="InvalidOperationException">Αν τρέχουν ήδη <see cref="MaxConcurrentScans"/> scans.</exception>
    public long Start(ScanOptions options)
    {
        if (_running.Count >= MaxConcurrentScans)
            throw new InvalidOperationException($"Τρέχουν ήδη {MaxConcurrentScans} scans. Περίμενε να τελειώσει κάποιο.");

        var selected = _allModules
            .Where(m => m.Level <= options.Level)
            .Where(m => options.Modules.Count == 0 || options.Modules.Contains(m.Name))
            .ToList();

        var scanId = _store.CreateScan(options.Target, options.Level.ToString().ToLowerInvariant(),
            JsonSerializer.Serialize(options));
        var cts = new CancellationTokenSource(TimeSpan.FromHours(1));
        _running[scanId] = cts;

        var run = new ScanRun(scanId, options, selected, _store, _logger);
        _logger.LogInformation("Έναρξη scan #{ScanId} για {Target} ({Level}) με {Count} modules",
            scanId, options.Target, options.Level, selected.Count);
        _ = Task.Run(() => ExecuteAsync(run, cts));
        return scanId;
    }

    /// <summary>
    /// Τρέχει ένα scan και καταγράφει την τελική του κατάσταση (finished, stopped ή failed).
    /// </summary>
    /// <param name="run">Το scan.</param>
    /// <param name="cts">Η πηγή ακύρωσης του scan.</param>
    async Task ExecuteAsync(ScanRun run, CancellationTokenSource cts)
    {
        try
        {
            var started = DateTime.UtcNow;
            await run.RunAsync(cts.Token);
            _store.FinishScan(run.ScanId, "finished");
            _logger.LogInformation("Ολοκληρώθηκε το scan #{ScanId} σε {Seconds:0.0} s", run.ScanId, (DateTime.UtcNow - started).TotalSeconds);
        }
        catch (OperationCanceledException)
        {
            run.Log("engine", "warn", "Το scan σταμάτησε.");
            _logger.LogInformation("Το scan #{ScanId} σταμάτησε", run.ScanId);
            _store.FinishScan(run.ScanId, "stopped");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Scan {ScanId} failed", run.ScanId);
            _store.FinishScan(run.ScanId, "failed", ex.Message);
        }
        finally
        {
            _running.TryRemove(run.ScanId, out _);
            cts.Dispose();
        }
    }

    /// <summary>Σταματά ένα scan που τρέχει.</summary>
    /// <param name="scanId">Το id του scan.</param>
    /// <returns><c>true</c> αν το scan έτρεχε και σταμάτησε.</returns>
    public bool Stop(long scanId)
    {
        if (!_running.TryGetValue(scanId, out var cts)) return false;
        try
        {
            cts.Cancel();
            return true;
        }
        catch (ObjectDisposedException)
        {
            return false;   // τελείωσε ακριβώς εκείνη τη στιγμή
        }
    }
}
