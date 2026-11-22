using System.Net;
using AttackSurfaceMapper.Application.Abstractions;
using AttackSurfaceMapper.Application.Common;
using AttackSurfaceMapper.Application.Contracts;
using AttackSurfaceMapper.Application.Engine;
using AttackSurfaceMapper.Domain;
using Microsoft.Extensions.Logging;

namespace AttackSurfaceMapper.Application.Services;

/// <summary>
/// Οι use cases του app: έναρξη/διακοπή scans, ιστορικό, γράφος με σύγκριση και συσχετίσεις.
/// </summary>
/// <param name="manager">Ο manager των scans που τρέχουν.</param>
/// <param name="store">Η αποθήκευση.</param>
/// <param name="gitleaks">Η γέφυρα προς το Gitleaks Scanner.</param>
/// <param name="logger">Ο logger.</param>
public sealed class ScanAppService(
    ScanManager manager,
    IScanStore store,
    IGitleaksScannerClient gitleaks,
    ILogger<ScanAppService> logger)
{
    /// <summary>Επιστρέφει όλα τα modules με την περιγραφή και το επίπεδό τους.</summary>
    /// <returns>Τα modules.</returns>
    public List<ModuleInfo> ListModules() => manager.Modules
        .Select(m => new ModuleInfo(m.Name, m.Description, m.Level.ToString().ToLowerInvariant(), m.Watched, m.Produced))
        .ToList();

    /// <summary>Επιστρέφει το ιστορικό των scans, μαζί με το αν τρέχει ακόμα το καθένα.</summary>
    /// <returns>Τα scans.</returns>
    public List<ScanListItem> ListScans() =>
        store.ListScans().Select(s => new ScanListItem(s, manager.IsRunning(s.Id))).ToList();

    /// <summary>
    /// Ελέγχει το αίτημα και ξεκινά νέο scan στο background. Το footprint scan απαιτεί ρητή
    /// επιβεβαίωση ότι ο χρήστης έχει άδεια για τον στόχο.
    /// </summary>
    /// <param name="req">Το αίτημα.</param>
    /// <returns>Το id του νέου scan, ή σφάλμα.</returns>
    public Result<long> StartScan(StartScanRequest req)
    {
        var target = ParseTarget(req.Target);
        if (target is null)
            return Result<long>.Fail(ErrorKind.Validation, "Δώσε ένα έγκυρο domain, π.χ. example.com (όχι IP).");

        Footprint? level = req.Level?.ToLowerInvariant() switch
        {
            "footprint" => Footprint.Footprint,
            "passive" or null => Footprint.Passive,
            _ => null
        };
        if (level is null) return Result<long>.Fail(ErrorKind.Validation, "Το επίπεδο πρέπει να είναι passive ή footprint.");
        if (level >= Footprint.Footprint && !req.Authorized)
            return Result<long>.Fail(ErrorKind.Validation, "Το footprint scan συνδέεται στους servers του στόχου. Επιβεβαίωσε ότι έχεις άδεια.");

        try
        {
            return Result<long>.Ok(manager.Start(new ScanOptions(target, level.Value, req.Modules ?? [], req.Gitleaks)));
        }
        catch (InvalidOperationException ex)
        {
            logger.LogWarning("Απορρίφθηκε scan για {Target}: {Reason}", target, ex.Message);
            return Result<long>.Fail(ErrorKind.Conflict, ex.Message);
        }
    }

    /// <summary>
    /// Μετατρέπει ό,τι έγραψε ο χρήστης σε κανονικοποιημένο domain: αφαιρεί scheme, path και "www.",
    /// και απορρίπτει IP διευθύνσεις.
    /// </summary>
    /// <param name="raw">Το κείμενο του χρήστη (π.χ. "https://www.example.com/page").</param>
    /// <returns>Το domain (π.χ. "example.com"), ή <c>null</c> αν δεν είναι έγκυρο.</returns>
    public static string? ParseTarget(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        raw = raw.Trim();
        if (raw.Contains("://") && Uri.TryCreate(raw, UriKind.Absolute, out var uri)) raw = uri.Host;
        raw = raw.Split('/')[0];
        if (IPAddress.TryParse(raw, out _)) return null;
        var host = Scope.NormalizeHost(raw);
        if (host is null) return null;
        // "www.example.com" → "example.com", αλλά όχι "www.co.uk" → "co.uk" (που είναι κατάληξη, όχι domain).
        return host.StartsWith("www.") && host.Count(c => c == '.') >= 2 && !Scope.IsSecondLevelSuffix(host[4..])
            ? host[4..]
            : host;
    }

    /// <summary>Επιστρέφει τη σύνοψη ενός scan και πόσα events βρέθηκαν από κάθε τύπο.</summary>
    /// <param name="id">Το id.</param>
    /// <returns>Η σύνοψη, ή NotFound.</returns>
    public Result<ScanDetails> GetScan(long id)
    {
        var scan = store.GetScan(id);
        if (scan is null) return Result<ScanDetails>.Fail(ErrorKind.NotFound, $"Το scan #{id} δεν υπάρχει.");
        var counts = store.GetEvents(id).GroupBy(e => e.Type).ToDictionary(g => g.Key, g => g.Count());
        return Result<ScanDetails>.Ok(new ScanDetails(scan, manager.IsRunning(id), counts));
    }

    /// <summary>
    /// Επιστρέφει τον γράφο ενός scan, τη σύγκριση με το προηγούμενο ολοκληρωμένο scan του ίδιου
    /// στόχου στο ίδιο επίπεδο, και τα ευρήματα των κανόνων συσχέτισης.
    /// </summary>
    /// <param name="id">Το id.</param>
    /// <returns>Ο γράφος, ή NotFound.</returns>
    public Result<ScanGraph> GetGraph(long id)
    {
        var scan = store.GetScan(id);
        if (scan is null) return Result<ScanGraph>.Fail(ErrorKind.NotFound, $"Το scan #{id} δεν υπάρχει.");

        var events = store.GetEvents(id);
        var edges = store.GetEdges(id);
        var running = manager.IsRunning(id);

        var prevId = store.GetPreviousScanId(scan);
        var diff = prevId is long p
            ? ScanDiff.Compare(p, store.GetEvents(p), events, running)
            : new ScanDiff(null, [], []);
        // Οι συσχετίσεις υπολογίζονται μόνο σε ολοκληρωμένο scan: σε μισά δεδομένα θα έβγαιναν λάθος συμπεράσματα.
        var correlations = running ? [] : CorrelationEngine.Run(events, edges);

        return Result<ScanGraph>.Ok(new ScanGraph(events, edges, diff, correlations));
    }

    /// <summary>Επιστρέφει το log ενός scan.</summary>
    /// <param name="id">Το id.</param>
    /// <returns>Οι γραμμές του log.</returns>
    public List<LogLine> GetLog(long id) => store.GetLog(id);

    /// <summary>Σταματά ένα scan που τρέχει.</summary>
    /// <param name="id">Το id.</param>
    /// <returns><c>true</c>, ή NotFound αν δεν έτρεχε.</returns>
    public Result<bool> Stop(long id) =>
        manager.Stop(id) ? Result<bool>.Ok(true) : Result<bool>.Fail(ErrorKind.NotFound, "Το scan δεν τρέχει.");

    /// <summary>Διαγράφει ένα scan που δεν τρέχει.</summary>
    /// <param name="id">Το id.</param>
    /// <returns><c>true</c>, ή Conflict/NotFound.</returns>
    public Result<bool> Delete(long id)
    {
        if (manager.IsRunning(id)) return Result<bool>.Fail(ErrorKind.Conflict, "Το scan τρέχει ακόμα. Σταμάτησέ το πρώτα.");
        if (!store.DeleteScan(id)) return Result<bool>.Fail(ErrorKind.NotFound, $"Το scan #{id} δεν υπάρχει.");
        logger.LogInformation("Διαγράφηκε το scan #{ScanId}", id);
        return Result<bool>.Ok(true);
    }

    /// <summary>Ελέγχει αν το Gitleaks Scanner τρέχει.</summary>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Η κατάστασή του.</returns>
    public Task<GitleaksHealth> GitleaksHealthAsync(CancellationToken ct) => gitleaks.CheckHealthAsync(ct);
}
