using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using AttackSurfaceMapper.Engine;

namespace AttackSurfaceMapper.Modules;

/// <summary>
/// Συνδέεται στη θύρα 443 κάθε host και ελέγχει το certificate: εκδότη, λήξη, αν ταιριάζει
/// στο hostname και αν είναι έμπιστο. Τα επιπλέον hostnames του certificate (SANs) γίνονται νέοι στόχοι.
/// </summary>
public sealed class SslCertModule : IModule
{
    /// <summary>Πόσες ημέρες πριν από τη λήξη θεωρείται ότι το certificate "λήγει σύντομα".</summary>
    const int ExpiringDays = 21;

    /// <inheritdoc/>
    public string Name => "ssl_cert";
    /// <inheritdoc/>
    public string Description => "Έλεγχος SSL certificate (λήξη, hostname, εμπιστοσύνη) και νέα hostnames από τα SANs.";
    /// <inheritdoc/>
    public Footprint Level => Footprint.Footprint;
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Watched { get; } = [EventTypes.Domain, EventTypes.Host];
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Produced { get; } =
        [EventTypes.CertIssuer, EventTypes.CertExpired, EventTypes.CertExpiring, EventTypes.CertMismatch,
         EventTypes.CertUntrusted, EventTypes.Host, EventTypes.AffiliateHost];

    /// <summary>
    /// Κάνει TLS handshake με τον host, διαβάζει το certificate και εκπέμπει ό,τι βρει.
    /// Αν ο host δεν ακούει στο 443, απλώς επιστρέφει.
    /// </summary>
    /// <param name="e">Το hostname.</param>
    /// <param name="ctx">Το context του scan.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Ένα task που ολοκληρώνεται όταν τελειώσει ο έλεγχος.</returns>
    public async Task HandleAsync(ScanEvent e, ScanContext ctx, CancellationToken ct)
    {
        var result = await HandshakeAsync(e.Data, ct);
        if (result is null) return;
        var (cert, errors) = result.Value;
        using (cert)
        {
            ctx.Emit(EventTypes.CertIssuer, IssuerName(cert), e);

            var now = DateTime.UtcNow;
            var expired = cert.NotAfter.ToUniversalTime() < now;
            if (expired)
                ctx.Emit(EventTypes.CertExpired, $"{e.Data}: έληξε στις {cert.NotAfter:yyyy-MM-dd}", e, "high");
            else if (cert.NotAfter.ToUniversalTime() - now < TimeSpan.FromDays(ExpiringDays))
                ctx.Emit(EventTypes.CertExpiring, $"{e.Data}: λήγει στις {cert.NotAfter:yyyy-MM-dd}", e, "medium");

            var sans = SubjectNames(cert);
            if (errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
                ctx.Emit(EventTypes.CertMismatch, $"{e.Data}: το certificate είναι για {string.Join(", ", sans.Take(3))}", e, "medium");
            if (!expired && errors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors))
                ctx.Emit(EventTypes.CertUntrusted, $"{e.Data}: μη έμπιστο certificate (self-signed ή ελλιπής αλυσίδα)", e, "medium");

            foreach (var name in sans) ctx.Emit(EventTypes.Host, name, e);
        }
    }

    /// <summary>
    /// Ανοίγει σύνδεση TLS στη θύρα 443 (μόνο σε δημόσια IP) και επιστρέφει το certificate
    /// του server μαζί με τα σφάλματα επικύρωσης.
    /// </summary>
    /// <param name="host">Το hostname (στέλνεται και ως SNI).</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Το certificate και τα σφάλματα, ή <c>null</c> αν η σύνδεση απέτυχε.</returns>
    static async Task<(X509Certificate2 Cert, SslPolicyErrors Errors)?> HandshakeAsync(string host, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        try
        {
            var socket = await NetGuard.ConnectAsync(host, 443, timeout.Token);
            await using var ssl = new SslStream(new NetworkStream(socket, ownsSocket: true), leaveInnerStreamOpen: false);
            var errors = SslPolicyErrors.None;
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = host,
                // Δεχόμαστε κάθε certificate για να το εξετάσουμε· τα σφάλματα τα κρατάμε.
                RemoteCertificateValidationCallback = (_, _, _, err) => { errors = err; return true; }
            }, timeout.Token);

            if (ssl.RemoteCertificate is null) return null;
            var cert = ssl.RemoteCertificate as X509Certificate2
                       ?? X509CertificateLoader.LoadCertificate(ssl.RemoteCertificate.GetRawCertData());
            return (cert, errors);
        }
        catch (Exception ex) when (ex is SocketException or IOException or AuthenticationException
                                       or HttpRequestException or OperationCanceledException && !ct.IsCancellationRequested)
        {
            return null;   // δεν ακούει στο 443, δεν έχει δημόσια IP, ή timeout
        }
    }

    /// <summary>
    /// Επιστρέφει τον εκδότη του certificate σε αναγνώσιμη μορφή, π.χ. "Let's Encrypt (R11)".
    /// </summary>
    /// <param name="cert">Το certificate.</param>
    /// <returns>Οργανισμός και common name του εκδότη.</returns>
    static string IssuerName(X509Certificate2 cert)
    {
        var cn = cert.GetNameInfo(X509NameType.SimpleName, forIssuer: true);
        var org = cert.IssuerName.EnumerateRelativeDistinguishedNames()
            .FirstOrDefault(r => r.GetSingleElementType().Value == "2.5.4.10")?.GetSingleElementValue();
        return org is null || org == cn ? cn : $"{org} ({cn})";
    }

    /// <summary>
    /// Επιστρέφει τα hostnames που καλύπτει το certificate (Subject Alternative Names, ή το CN αν δεν υπάρχουν).
    /// </summary>
    /// <param name="cert">Το certificate.</param>
    /// <returns>Τα hostnames.</returns>
    static List<string> SubjectNames(X509Certificate2 cert)
    {
        var sans = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>()
            .SelectMany(x => x.EnumerateDnsNames())
            .ToList();
        if (sans.Count == 0) sans.Add(cert.GetNameInfo(X509NameType.DnsName, forIssuer: false));
        return sans;
    }
}
