using System.Net.Http.Json;
using System.Text.Json;
using AttackSurfaceMapper.Application.Abstractions;
using AttackSurfaceMapper.Application.Common;
using AttackSurfaceMapper.Application.Contracts;

namespace AttackSurfaceMapper.Infrastructure.Network;

/// <summary>Υλοποίηση του <see cref="IGitleaksScannerClient"/> μέσω του HTTP API του Gitleaks Scanner.</summary>
/// <param name="http">Το factory των HTTP clients.</param>
public sealed class GitleaksScannerClient(IHttpClientFactory http) : IGitleaksScannerClient
{
    /// <inheritdoc/>
    public async Task<GitleaksHealth> CheckHealthAsync(CancellationToken ct)
    {
        var client = http.CreateClient(HttpClients.Gitleaks);
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(3));
            using var res = await client.GetAsync("api/health", timeout.Token);
            return new GitleaksHealth(res.IsSuccessStatusCode, client.BaseAddress);
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException && !ct.IsCancellationRequested)
        {
            return new GitleaksHealth(false, client.BaseAddress);
        }
    }

    /// <inheritdoc/>
    public async Task<Result<GitleaksScanResult>> ScanRepositoryAsync(string repoUrl, CancellationToken ct)
    {
        var client = http.CreateClient(HttpClients.Gitleaks);
        try
        {
            using var res = await client.PostAsJsonAsync("api/scan", new { source = repoUrl, fullHistory = true }, ct);
            using var doc = await JsonDocument.ParseAsync(await res.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
            if (!res.IsSuccessStatusCode)
            {
                var err = doc.RootElement.TryGetProperty("error", out var e) ? e.GetString() : res.StatusCode.ToString();
                return Result<GitleaksScanResult>.Fail(ErrorKind.Failure, err ?? "άγνωστο σφάλμα");
            }
            var total = doc.RootElement.GetProperty("stats").GetProperty("total").GetInt32();
            var scanId = doc.RootElement.GetProperty("scan").GetProperty("id").GetInt64();
            var baseUrl = client.BaseAddress?.ToString().TrimEnd('/');
            return Result<GitleaksScanResult>.Ok(new GitleaksScanResult(scanId, total, $"{baseUrl}/#/scan/{scanId}"));
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or KeyNotFoundException && !ct.IsCancellationRequested)
        {
            return Result<GitleaksScanResult>.Fail(ErrorKind.Failure, ex.Message);
        }
    }
}
