using System.Net;
using System.Net.Sockets;
using System.Text;
using AttackSurfaceMapper.Infrastructure.Network;

namespace AttackSurfaceMapper.Infrastructure.Modules.Active;

/// <summary>Μια ανοιχτή θύρα.</summary>
/// <param name="Port">Η θύρα.</param>
/// <param name="Banner">Η πρώτη γραμμή που έστειλε η υπηρεσία, αν έστειλε (π.χ. "SSH-2.0-OpenSSH_9.6").</param>
public record OpenPort(int Port, string? Banner);

/// <summary>
/// TCP connect scan: για κάθε θύρα δοκιμάζει να ανοίξει σύνδεση (χωρίς raw sockets ή δικαιώματα
/// διαχειριστή) και, όπου η υπηρεσία μιλά πρώτη (SSH, FTP, SMTP…), διαβάζει το banner.
/// </summary>
/// <param name="allowConnect">
/// Αποφασίζει σε ποιες IP επιτρέπεται σύνδεση. Στην εφαρμογή είναι το <see cref="NetGuard.IsPublic"/>
/// (ποτέ ιδιωτικές IP)· τα tests δίνουν άλλο, για να ελέγξουν τον scanner σε τοπικό server.
/// </param>
/// <param name="bannerPorts">Θύρες όπου διαβάζεται banner (<c>null</c>: οι γνωστές, βλ. <see cref="DefaultBannerPorts"/>).</param>
public sealed class PortScanner(Func<IPAddress, bool> allowConnect, IReadOnlySet<int>? bannerPorts = null)
{
    /// <summary>Θύρες όπου η υπηρεσία στέλνει πρώτη ένα banner (SSH, FTP, SMTP, POP3, IMAP…).</summary>
    public static readonly IReadOnlySet<int> DefaultBannerPorts = new HashSet<int> { 21, 22, 23, 25, 110, 143, 465, 587, 993, 995 };

    readonly IReadOnlySet<int> _bannerPorts = bannerPorts ?? DefaultBannerPorts;

    /// <summary>Scanner για την εφαρμογή: συνδέεται μόνο σε δημόσιες IP.</summary>
    public static PortScanner Public { get; } = new(NetGuard.IsPublic);

    /// <summary>
    /// Ελέγχει ποιες από τις θύρες είναι ανοιχτές, με περιορισμένο πλήθος ταυτόχρονων συνδέσεων.
    /// </summary>
    /// <param name="ip">Η IP.</param>
    /// <param name="ports">Οι θύρες.</param>
    /// <param name="concurrency">Πόσες συνδέσεις ταυτόχρονα (για να μην κατακλυστεί ο στόχος).</param>
    /// <param name="timeout">Πόσο περιμένουμε κάθε σύνδεση.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Οι ανοιχτές θύρες, ταξινομημένες.</returns>
    /// <exception cref="InvalidOperationException">Αν η IP δεν επιτρέπεται (π.χ. ιδιωτική).</exception>
    public async Task<List<OpenPort>> ScanAsync(IPAddress ip, IEnumerable<int> ports, int concurrency, TimeSpan timeout,
        CancellationToken ct)
    {
        if (!allowConnect(ip)) throw new InvalidOperationException($"Δεν επιτρέπεται σύνδεση στην {ip}.");

        using var slots = new SemaphoreSlim(concurrency);
        var tasks = ports.Distinct().Select(async port =>
        {
            await slots.WaitAsync(ct);
            try { return await ProbeAsync(ip, port, timeout, ct); }
            finally { slots.Release(); }
        });
        return (await Task.WhenAll(tasks)).OfType<OpenPort>().OrderBy(p => p.Port).ToList();
    }

    /// <summary>Δοκιμάζει μία θύρα και, αν είναι ανοιχτή, διαβάζει το banner όπου υπάρχει.</summary>
    /// <param name="ip">Η IP.</param>
    /// <param name="port">Η θύρα.</param>
    /// <param name="timeout">Πόσο περιμένουμε τη σύνδεση.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Η ανοιχτή θύρα, ή <c>null</c> αν είναι κλειστή/φιλτραρισμένη.</returns>
    async Task<OpenPort?> ProbeAsync(IPAddress ip, int port, TimeSpan timeout, CancellationToken ct)
    {
        using var socket = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try
        {
            await socket.ConnectAsync(new IPEndPoint(ip, port), cts.Token);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException && !ct.IsCancellationRequested)
        {
            return null;
        }
        return new OpenPort(port, _bannerPorts.Contains(port) ? await ReadBannerAsync(socket, ct) : null);
    }

    /// <summary>
    /// Διαβάζει την πρώτη γραμμή που στέλνει η υπηρεσία, κρατώντας μόνο εκτυπώσιμους χαρακτήρες
    /// (το banner μπαίνει στο UI και δεν πρέπει να περιέχει τίποτα "περίεργο").
    /// </summary>
    /// <param name="socket">Η ανοιχτή σύνδεση.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Το banner (έως 100 χαρακτήρες), ή <c>null</c>.</returns>
    static async Task<string?> ReadBannerAsync(Socket socket, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(2));
        var buffer = new byte[256];
        try
        {
            var read = await socket.ReceiveAsync(buffer, SocketFlags.None, cts.Token);
            if (read <= 0) return null;
            var line = Encoding.ASCII.GetString(buffer, 0, read).Split('\n')[0];
            var clean = new string(line.Where(c => c >= ' ' && c < 127).ToArray()).Trim();
            return clean.Length == 0 ? null : clean.Length > 100 ? clean[..100] : clean;
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException && !ct.IsCancellationRequested)
        {
            return null;
        }
    }
}
