using System.Net;
using AttackSurfaceMapper.Application.Abstractions;
using AttackSurfaceMapper.Application.Engine;
using AttackSurfaceMapper.Domain;

namespace AttackSurfaceMapper.Infrastructure.Modules.Active;

/// <summary>
/// ACTIVE: ελέγχει ~45 κρίσιμες θύρες TCP σε κάθε δημόσια IP του στόχου (βάσεις δεδομένων,
/// απομακρυσμένη πρόσβαση, διαχειριστικά APIs) και διαβάζει τα banners.
/// </summary>
/// <param name="scanner">Ο scanner (στην εφαρμογή: <see cref="PortScanner.Public"/>, μόνο δημόσιες IP).</param>
public sealed class PortScanModule(PortScanner scanner) : IModule
{
    /// <inheritdoc/>
    public string Name => "port_scan";
    /// <inheritdoc/>
    public string Description => "Έλεγχος ~45 κρίσιμων θυρών TCP (βάσεις δεδομένων, RDP, SSH, Docker…) με ανάγνωση banner.";
    /// <inheritdoc/>
    public Footprint Level => Footprint.Active;
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Watched { get; } = [EventTypes.Ip, EventTypes.Ip6];
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Produced { get; } = [EventTypes.TcpPortOpen];
    /// <inheritdoc/>
    /// <remarks>Χαμηλό όριο IP: ένα port scan είναι η πιο "θορυβώδης" ενέργεια του app.</remarks>
    public int MaxTargets => 30;

    /// <summary>
    /// Σκανάρει τις θύρες του <see cref="PortCatalog"/> στην IP (8 συνδέσεις ταυτόχρονα, 2s ανά
    /// θύρα) και εκπέμπει κάθε ανοιχτή θύρα με τον κίνδυνό της.
    /// </summary>
    /// <param name="e">Η IP.</param>
    /// <param name="ctx">Το context του scan.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Ένα task που ολοκληρώνεται όταν τελειώσει το scan της IP.</returns>
    public async Task HandleAsync(ScanEvent e, ScanContext ctx, CancellationToken ct)
    {
        if (!IPAddress.TryParse(e.Data, out var ip)) return;
        var open = await scanner.ScanAsync(ip, PortCatalog.All.Select(p => p.Port), concurrency: 8,
            timeout: TimeSpan.FromSeconds(2), ct);

        foreach (var p in open)
        {
            var info = PortCatalog.Get(p.Port);
            // Ένα banner με αριθμό έκδοσης αυξάνει τον κίνδυνο από "info" σε "low" (διευκολύνει την εύρεση ευπαθειών).
            var risk = info.Risk == "info" && p.Banner is { } b && b.Any(char.IsDigit) ? "low" : info.Risk;
            ctx.Emit(EventTypes.TcpPortOpen, PortCatalog.Format(ip.ToString(), p.Port, p.Banner), e, risk);
        }
        ctx.Log($"{ip}: {open.Count} ανοιχτές θύρες από {PortCatalog.All.Count}.");
    }
}
