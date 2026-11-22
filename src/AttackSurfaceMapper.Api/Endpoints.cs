using AttackSurfaceMapper.Application.Common;
using AttackSurfaceMapper.Application.Contracts;
using AttackSurfaceMapper.Application.Services;
using AttackSurfaceMapper.Domain;

namespace AttackSurfaceMapper.Api;

/// <summary>
/// Τα HTTP endpoints. Κάθε endpoint καλεί μια use case της Application και μεταφράζει το
/// <see cref="Result{T}"/> σε HTTP απάντηση· δεν περιέχει επιχειρησιακή λογική.
/// </summary>
public static class Endpoints
{
    /// <summary>Καταχωρεί όλα τα endpoints του API.</summary>
    /// <param name="app">Η εφαρμογή.</param>
    public static void MapEndpoints(this WebApplication app)
    {
        var api = app.MapGroup("/api");
        api.MapGet("/modules", (ScanAppService s) => Results.Ok(s.ListModules()));
        api.MapGet("/types", () => Results.Ok(EventTypes.Meta));
        api.MapGet("/scans", (ScanAppService s) => Results.Ok(s.ListScans()));
        api.MapPost("/scans", StartScan);
        api.MapGet("/scans/{id:long}", (long id, ScanAppService s) => s.GetScan(id).ToHttp());
        api.MapGet("/scans/{id:long}/graph", (long id, ScanAppService s) => s.GetGraph(id).ToHttp());
        api.MapGet("/scans/{id:long}/log", (long id, ScanAppService s) => Results.Ok(s.GetLog(id)));
        api.MapPost("/scans/{id:long}/stop", (long id, ScanAppService s) => s.Stop(id).ToNoContent());
        api.MapDelete("/scans/{id:long}", (long id, ScanAppService s) => s.Delete(id).ToNoContent());
        api.MapGet("/gitleaks/health", async (ScanAppService s, CancellationToken ct) => Results.Ok(await s.GitleaksHealthAsync(ct)));
    }

    /// <summary>Ξεκινά νέο scan.</summary>
    /// <param name="req">Το αίτημα.</param>
    /// <param name="scans">Η use case.</param>
    /// <returns><c>{ id }</c> του νέου scan, ή σφάλμα.</returns>
    static IResult StartScan(StartScanRequest req, ScanAppService scans)
    {
        var result = scans.StartScan(req);
        return result.IsSuccess ? Results.Ok(new { id = result.Value }) : Error(result.Error!);
    }

    /// <summary>Μεταφράζει ένα αποτέλεσμα σε HTTP: 200 με την τιμή, ή το status του σφάλματος.</summary>
    /// <typeparam name="T">Ο τύπος της τιμής.</typeparam>
    /// <param name="result">Το αποτέλεσμα.</param>
    /// <returns>Η HTTP απάντηση.</returns>
    static IResult ToHttp<T>(this Result<T> result) => result.IsSuccess ? Results.Ok(result.Value) : Error(result.Error!);

    /// <summary>Όπως η <see cref="ToHttp{T}"/>, αλλά με 204 (χωρίς σώμα) στην επιτυχία.</summary>
    /// <typeparam name="T">Ο τύπος της τιμής.</typeparam>
    /// <param name="result">Το αποτέλεσμα.</param>
    /// <returns>Η HTTP απάντηση.</returns>
    static IResult ToNoContent<T>(this Result<T> result) => result.IsSuccess ? Results.NoContent() : Error(result.Error!);

    /// <summary>Μεταφράζει ένα σφάλμα της Application σε HTTP status με σώμα <c>{ "error": "…" }</c>.</summary>
    /// <param name="error">Το σφάλμα.</param>
    /// <returns>Η HTTP απάντηση.</returns>
    static IResult Error(AppError error) => Results.Json(new { error = error.Message }, statusCode: error.Kind switch
    {
        ErrorKind.Validation => StatusCodes.Status400BadRequest,
        ErrorKind.NotFound => StatusCodes.Status404NotFound,
        ErrorKind.Conflict => StatusCodes.Status409Conflict,
        _ => StatusCodes.Status500InternalServerError,
    });
}
