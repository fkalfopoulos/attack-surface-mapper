using AttackSurfaceMapper.Application.Common;
using AttackSurfaceMapper.Application.Contracts;

namespace AttackSurfaceMapper.Application.Abstractions;

/// <summary>
/// Η γέφυρα προς το Gitleaks Scanner (ξεχωριστό app). Υλοποιείται στην Infrastructure με HTTP.
/// </summary>
public interface IGitleaksScannerClient
{
    /// <summary>Ελέγχει αν το Gitleaks Scanner τρέχει και απαντά.</summary>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Αν είναι διαθέσιμο και σε ποιο URL.</returns>
    Task<GitleaksHealth> CheckHealthAsync(CancellationToken ct);

    /// <summary>Ζητά scan ενός repository (με όλο το ιστορικό) και περιμένει το αποτέλεσμα.</summary>
    /// <param name="repoUrl">Το https URL του repo.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Το αποτέλεσμα, ή σφάλμα.</returns>
    Task<Result<GitleaksScanResult>> ScanRepositoryAsync(string repoUrl, CancellationToken ct);
}
