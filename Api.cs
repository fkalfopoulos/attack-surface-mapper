using System.Net;
using AttackSurfaceMapper.Data;
using AttackSurfaceMapper.Engine;

namespace AttackSurfaceMapper;

/// <summary>Το σώμα του αιτήματος για νέο scan.</summary>
/// <param name="Target">Το domain (δέχεται και URL, από το οποίο κρατά μόνο το host).</param>
/// <param name="Level">"passive" ή "footprint".</param>
/// <param name="Modules">Τα modules που θα τρέξουν· κενό σημαίνει όλα του επιπέδου.</param>
/// <param name="Gitleaks">Αν τα repos θα σκαναριστούν με το Gitleaks Scanner.</param>
/// <param name="Authorized">Επιβεβαίωση του χρήστη ότι έχει άδεια για footprint scan στον στόχο.</param>
public record StartScanRequest(string? Target, string? Level, string[]? Modules, bool Gitleaks, bool Authorized);

/// <summary>
/// Τα HTTP endpoints του API. Κάθε endpoint είναι μια method, για να είναι ευανάγνωστο και τεκμηριωμένο.
/// </summary>
public static class Api
{
    /// <summary>Καταχωρεί όλα τα endpoints του API στην εφαρμογή.</summary>
    /// <param name="app">Η εφαρμογή.</param>
    public static void MapApi(this WebApplication app)
    {
        var api = app.MapGroup("/api");
        api.MapGet("/modules", ListModules);
        api.MapGet("/types", ListTypes);
        api.MapGet("/scans", ListScans);
        api.MapPost("/scans", StartScan);
        api.MapGet("/scans/{id:long}", GetScan);
        api.MapGet("/scans/{id:long}/graph", GetGraph);
        api.MapGet("/scans/{id:long}/log", GetLog);
        api.MapPost("/scans/{id:long}/stop", StopScan);
        api.MapDelete("/scans/{id:long}", DeleteScan);
        api.MapGet("/gitleaks/health", GitleaksHealth);
    }

    /// <summary>Επιστρέφει όλα τα modules με την περιγραφή, το επίπεδο και τους τύπους που παράγουν.</summary>
    /// <param name="manager">Ο manager των scans.</param>
    /// <returns>Η λίστα των modules.</returns>
    static IResult ListModules(ScanManager manager) => Results.Ok(manager.Modules.Select(m => new
    {
        m.Name,
        m.Description,
        level = m.Level.ToString().ToLowerInvariant(),
        m.Watched,
        m.Produced
    }));

    /// <summary>Επιστρέφει την ελληνική ετικέτα και την ομάδα κάθε τύπου event, για το UI.</summary>
    /// <returns>Λεξικό τύπος → ετικέτα/ομάδα.</returns>
    static IResult ListTypes() => Results.Ok(EventTypes.Meta);

    /// <summary>Επιστρέφει το ιστορικό των scans, μαζί με το αν τρέχει ακόμα το καθένα.</summary>
    /// <param name="store">Η βάση.</param>
    /// <param name="manager">Ο manager των scans.</param>
    /// <returns>Η λίστα των scans.</returns>
    static IResult ListScans(Store store, ScanManager manager) =>
        Results.Ok(store.ListScans().Select(s => new { scan = s, running = manager.IsRunning(s.Id) }));

    /// <summary>
    /// Ελέγχει το αίτημα και ξεκινά νέο scan στο background.
    /// </summary>
    /// <param name="req">Το αίτημα.</param>
    /// <param name="manager">Ο manager των scans.</param>
    /// <returns>Το id του νέου scan, ή σφάλμα 400 αν το αίτημα είναι άκυρο.</returns>
    static IResult StartScan(StartScanRequest req, ScanManager manager)
    {
        var target = ParseTarget(req.Target);
        if (target is null)
            return Results.BadRequest(new { error = "Δώσε ένα έγκυρο domain, π.χ. example.com (όχι IP)." });

        var level = req.Level?.ToLowerInvariant() switch
        {
            "footprint" => Footprint.Footprint,
            "passive" or null => Footprint.Passive,
            _ => (Footprint?)null
        };
        if (level is null) return Results.BadRequest(new { error = "Το επίπεδο πρέπει να είναι passive ή footprint." });
        if (level >= Footprint.Footprint && !req.Authorized)
            return Results.BadRequest(new { error = "Το footprint scan συνδέεται στους servers του στόχου. Επιβεβαίωσε ότι έχεις άδεια." });

        try
        {
            var id = manager.Start(new ScanOptions(target, level.Value, req.Modules ?? [], req.Gitleaks));
            return Results.Ok(new { id });
        }
        catch (InvalidOperationException ex)
        {
            return Results.Conflict(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Μετατρέπει ό,τι έγραψε ο χρήστης σε κανονικοποιημένο domain: αφαιρεί scheme, path και "www.",
    /// και απορρίπτει IP διευθύνσεις.
    /// </summary>
    /// <param name="raw">Το κείμενο του χρήστη (π.χ. "https://www.example.com/page").</param>
    /// <returns>Το domain (π.χ. "example.com"), ή <c>null</c> αν δεν είναι έγκυρο.</returns>
    static string? ParseTarget(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        raw = raw.Trim();
        if (raw.Contains("://") && Uri.TryCreate(raw, UriKind.Absolute, out var uri)) raw = uri.Host;
        raw = raw.Split('/')[0];
        if (IPAddress.TryParse(raw, out _)) return null;
        var host = Scope.NormalizeHost(raw);
        if (host is null) return null;
        return host.StartsWith("www.") && host.Count(c => c == '.') >= 2 ? host[4..] : host;
    }

    /// <summary>Επιστρέφει τη σύνοψη ενός scan και πόσα events βρέθηκαν από κάθε τύπο.</summary>
    /// <param name="id">Το id του scan.</param>
    /// <param name="store">Η βάση.</param>
    /// <param name="manager">Ο manager των scans.</param>
    /// <returns>Η σύνοψη, ή 404 αν δεν υπάρχει.</returns>
    static IResult GetScan(long id, Store store, ScanManager manager)
    {
        var scan = store.GetScan(id);
        if (scan is null) return Results.NotFound();
        var counts = store.GetEvents(id).GroupBy(e => e.Type).ToDictionary(g => g.Key, g => g.Count());
        return Results.Ok(new { scan, running = manager.IsRunning(id), counts });
    }

    /// <summary>Επιστρέφει όλα τα events (κόμβους) και τις ακμές ενός scan, για τον γράφο και τους πίνακες.</summary>
    /// <param name="id">Το id του scan.</param>
    /// <param name="store">Η βάση.</param>
    /// <returns>Τα events και οι ακμές, ή 404 αν δεν υπάρχει το scan.</returns>
    static IResult GetGraph(long id, Store store) =>
        store.GetScan(id) is null
            ? Results.NotFound()
            : Results.Ok(new { events = store.GetEvents(id), edges = store.GetEdges(id) });

    /// <summary>Επιστρέφει το log ενός scan.</summary>
    /// <param name="id">Το id του scan.</param>
    /// <param name="store">Η βάση.</param>
    /// <returns>Οι γραμμές του log.</returns>
    static IResult GetLog(long id, Store store) => Results.Ok(store.GetLog(id));

    /// <summary>Σταματά ένα scan που τρέχει.</summary>
    /// <param name="id">Το id του scan.</param>
    /// <param name="manager">Ο manager των scans.</param>
    /// <returns>204 αν σταμάτησε, 404 αν δεν έτρεχε.</returns>
    static IResult StopScan(long id, ScanManager manager) =>
        manager.Stop(id) ? Results.NoContent() : Results.NotFound();

    /// <summary>Διαγράφει ένα scan (αν τρέχει, το σταματά πρώτα).</summary>
    /// <param name="id">Το id του scan.</param>
    /// <param name="store">Η βάση.</param>
    /// <param name="manager">Ο manager των scans.</param>
    /// <returns>204 αν διαγράφηκε, 404 αν δεν υπήρχε, 409 αν τρέχει ακόμα.</returns>
    static IResult DeleteScan(long id, Store store, ScanManager manager)
    {
        if (manager.IsRunning(id))
            return Results.Conflict(new { error = "Το scan τρέχει ακόμα. Σταμάτησέ το πρώτα." });
        return store.DeleteScan(id) ? Results.NoContent() : Results.NotFound();
    }

    /// <summary>Ελέγχει αν το Gitleaks Scanner τρέχει και απαντά.</summary>
    /// <param name="http">Το factory των HTTP clients.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Αν είναι διαθέσιμο και σε ποιο URL.</returns>
    static async Task<IResult> GitleaksHealth(IHttpClientFactory http, CancellationToken ct)
    {
        var client = http.CreateClient(HttpClients.Gitleaks);
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(3));
            using var res = await client.GetAsync("api/health", timeout.Token);
            return Results.Ok(new { available = res.IsSuccessStatusCode, url = client.BaseAddress });
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException)
        {
            return Results.Ok(new { available = false, url = client.BaseAddress });
        }
    }
}
