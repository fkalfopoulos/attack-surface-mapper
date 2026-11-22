using System.Net;
using System.Net.Sockets;

namespace AttackSurfaceMapper.Infrastructure.Network;

/// <summary>
/// Εμποδίζει τις συνδέσεις προς μη δημόσιες διευθύνσεις (προστασία από SSRF).
/// </summary>
/// <remarks>
/// Ένα domain μπορεί, κατά λάθος ή επίτηδες, να δείχνει σε 127.0.0.1, 10.x ή 169.254.169.254.
/// Τότε το scan θα χτυπούσε υπηρεσίες του δικού σου υπολογιστή ή του τοπικού δικτύου.
/// </remarks>
public static class NetGuard
{
    /// <summary>
    /// Ελέγχει αν μια IP είναι δημόσια, δηλαδή όχι loopback, ιδιωτική, link-local, CGNAT ή multicast.
    /// </summary>
    /// <param name="ip">Η διεύθυνση που ελέγχεται (IPv4 ή IPv6).</param>
    /// <returns><c>true</c> αν η διεύθυνση είναι δημόσια και επιτρέπεται η σύνδεση σε αυτήν.</returns>
    public static bool IsPublic(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return false;

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return !(b[0] == 0 || b[0] == 10 || b[0] == 127
                || (b[0] == 100 && b[1] >= 64 && b[1] <= 127)   // CGNAT
                || (b[0] == 169 && b[1] == 254)                  // link-local, cloud metadata
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 192 && b[1] == 0 && b[2] == 0)
                || (b[0] == 198 && (b[1] == 18 || b[1] == 19))  // benchmarking
                || b[0] >= 224);                                 // multicast, reserved
        }
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var b = ip.GetAddressBytes();
            return !(ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast
                || (b[0] & 0xFE) == 0xFC);                       // unique local fc00::/7
        }
        return false;
    }

    /// <summary>
    /// Βρίσκει τις IP ενός hostname και επιστρέφει την πρώτη δημόσια.
    /// </summary>
    /// <param name="host">Το hostname που θα γίνει resolve.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Η πρώτη δημόσια IP του host.</returns>
    /// <exception cref="HttpRequestException">Αν ο host δεν έχει καμία δημόσια IP.</exception>
    public static async Task<IPAddress> ResolvePublicAsync(string host, CancellationToken ct)
    {
        var addrs = await Dns.GetHostAddressesAsync(host, ct);
        return addrs.FirstOrDefault(IsPublic)
            ?? throw new HttpRequestException($"Το {host} δεν έχει δημόσια IP: η σύνδεση μπλοκαρίστηκε.");
    }

    /// <summary>
    /// Ανοίγει TCP σύνδεση σε έναν host, μόνο αν αυτός έχει δημόσια IP.
    /// </summary>
    /// <remarks>
    /// Ο έλεγχος γίνεται στην IP στην οποία πραγματικά συνδεόμαστε, άρα δεν παρακάμπτεται
    /// με DNS rebinding (ένα δεύτερο DNS lookup που επιστρέφει άλλη IP).
    /// </remarks>
    /// <param name="host">Το hostname.</param>
    /// <param name="port">Η θύρα TCP.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Ένα συνδεδεμένο socket. Ο caller είναι υπεύθυνος για το Dispose.</returns>
    public static async Task<Socket> ConnectAsync(string host, int port, CancellationToken ct)
    {
        var ip = await ResolvePublicAsync(host, ct);
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(new IPEndPoint(ip, port), ct);
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Φτιάχνει HTTP handler για συνδέσεις προς τον στόχο, που συνδέεται μόνο σε δημόσιες IP
    /// και δεν ακολουθεί αυτόματα τα redirects.
    /// </summary>
    /// <returns>Ένας ρυθμισμένος <see cref="SocketsHttpHandler"/>.</returns>
    public static SocketsHttpHandler CreateHandler() => new()
    {
        AllowAutoRedirect = false,
        AutomaticDecompression = DecompressionMethods.All,
        ConnectTimeout = TimeSpan.FromSeconds(8),
        PooledConnectionLifetime = TimeSpan.FromMinutes(2),
        // Τα προβλήματα των certificates τα αναφέρει το SslCert module· εδώ θέλουμε
        // να δούμε τη σελίδα ακόμα κι αν το certificate είναι λάθος.
        SslOptions = { RemoteCertificateValidationCallback = (_, _, _, _) => true },
        ConnectCallback = async (context, ct) =>
        {
            var socket = await ConnectAsync(context.DnsEndPoint.Host, context.DnsEndPoint.Port, ct);
            return new NetworkStream(socket, ownsSocket: true);
        }
    };
}
