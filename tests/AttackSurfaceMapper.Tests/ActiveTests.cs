using System.Net;
using System.Net.Sockets;
using System.Text;
using AttackSurfaceMapper.Application.Contracts;
using AttackSurfaceMapper.Application.Services;
using AttackSurfaceMapper.Domain;
using AttackSurfaceMapper.Infrastructure.Modules.Active;

namespace AttackSurfaceMapper.Tests;

/// <summary>Tests για τη Φάση 3: εξουσιοδότηση, port scan, θύρες, takeover και οι νέοι κανόνες.</summary>
public class ActiveTests
{
    /// <summary>Φτιάχνει αίτημα για active scan.</summary>
    /// <param name="authorized">Αν επιβεβαιώθηκε η άδεια.</param>
    /// <param name="confirm">Το domain που ξαναέγραψε ο χρήστης.</param>
    /// <param name="level">Το επίπεδο.</param>
    /// <returns>Το αίτημα.</returns>
    static StartScanRequest Req(bool authorized, string? confirm, string level = "active") =>
        new("example.com", level, null, false, authorized, confirm);

    /// <summary>Ελέγχει ότι το active scan απαιτεί και άδεια και να ξαναγραφτεί σωστά το domain.</summary>
    [Fact]
    public void Authorization_ActiveRequiresConsentAndTypedTarget()
    {
        Assert.NotNull(ScanAppService.CheckAuthorization(Req(false, "example.com"), "example.com").Error);
        Assert.NotNull(ScanAppService.CheckAuthorization(Req(true, null), "example.com").Error);
        Assert.NotNull(ScanAppService.CheckAuthorization(Req(true, "example.org"), "example.com").Error);

        var ok = ScanAppService.CheckAuthorization(Req(true, " https://WWW.example.com/ "), "example.com");
        Assert.Null(ok.Error);
        Assert.Equal(Footprint.Active, ok.Level);
    }

    /// <summary>Ελέγχει ότι το footprint θέλει μόνο άδεια, και το passive τίποτα.</summary>
    [Fact]
    public void Authorization_LowerLevels()
    {
        Assert.NotNull(ScanAppService.CheckAuthorization(Req(false, null, "footprint"), "example.com").Error);
        Assert.Null(ScanAppService.CheckAuthorization(Req(true, null, "footprint"), "example.com").Error);
        Assert.Null(ScanAppService.CheckAuthorization(Req(false, null, "passive"), "example.com").Error);
        Assert.NotNull(ScanAppService.CheckAuthorization(Req(true, null, "aggressive"), "example.com").Error);
    }

    /// <summary>
    /// Ελέγχει τον port scanner σε πραγματικό τοπικό server: βρίσκει την ανοιχτή θύρα και διαβάζει
    /// το banner, ενώ η κλειστή θύρα δεν εμφανίζεται.
    /// </summary>
    [Fact]
    public async Task PortScanner_FindsOpenPortAndReadsBanner()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var openPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        var server = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            await client.GetStream().WriteAsync(Encoding.ASCII.GetBytes("SSH-2.0-TestServer_1.0\r\n"));
            await Task.Delay(500);
        });

        int closedPort;
        using (var tmp = new TcpListener(IPAddress.Loopback, 0)) { tmp.Start(); closedPort = ((IPEndPoint)tmp.LocalEndpoint).Port; }

        // Τα tests επιτρέπουν το loopback (η εφαρμογή όχι, βλ. το επόμενο test) και διαβάζουν banner
        // στην τυχαία θύρα του listener, αφού οι θύρες 22/21 θέλουν δικαιώματα διαχειριστή.
        var scanner = new PortScanner(_ => true, new HashSet<int> { openPort });
        var open = await scanner.ScanAsync(IPAddress.Loopback, [openPort, closedPort], 4, TimeSpan.FromSeconds(2), CancellationToken.None);

        var port = Assert.Single(open);
        Assert.Equal(openPort, port.Port);
        Assert.Equal("SSH-2.0-TestServer_1.0", port.Banner);
        await server;
    }

    /// <summary>
    /// Ελέγχει την προστασία SSRF του scanner της εφαρμογής: αρνείται να σκανάρει τον δικό σου
    /// υπολογιστή ή το τοπικό δίκτυο, ακόμα κι αν ένα domain δείχνει εκεί.
    /// </summary>
    /// <param name="ip">Ιδιωτική διεύθυνση.</param>
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("192.168.1.1")]
    [InlineData("169.254.169.254")]
    public async Task PortScanner_Public_RefusesPrivateAddresses(string ip) =>
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            PortScanner.Public.ScanAsync(IPAddress.Parse(ip), [22], 1, TimeSpan.FromSeconds(1), CancellationToken.None));

    /// <summary>Ελέγχει ότι η τιμή μιας ανοιχτής θύρας γράφεται και διαβάζεται σωστά (IPv4 και IPv6).</summary>
    [Fact]
    public void PortCatalog_FormatAndParseRoundTrip()
    {
        Assert.Equal("203.0.113.7:6379 (Redis)", PortCatalog.Format("203.0.113.7", 6379, null));
        Assert.Equal("[2001:db8::1]:22 (SSH) · SSH-2.0-x", PortCatalog.Format("2001:db8::1", 22, "SSH-2.0-x"));
        Assert.True(PortCatalog.TryParse("[2001:db8::1]:3389 (RDP) · banner", out var rdp));
        Assert.Equal(PortCategory.RemoteAccess, rdp.Category);
        Assert.Equal("high", PortCatalog.Get(27017).Risk);
        Assert.Equal("άγνωστη", PortCatalog.Get(12345).Service);
    }

    /// <summary>Ελέγχει την αναγνώριση της υπηρεσίας από το CNAME και το fingerprint της σελίδας.</summary>
    [Fact]
    public void TakeoverFingerprints_MatchServiceAndBody()
    {
        var gh = TakeoverFingerprints.ForCname("acme.github.io.");
        Assert.Equal("GitHub Pages", gh?.Service);
        Assert.True(TakeoverFingerprints.Matches(gh!, "<h1>404</h1><p>There isn't a GitHub Pages site here.</p>"));
        Assert.False(TakeoverFingerprints.Matches(gh!, "<h1>Acme docs</h1>"));

        Assert.Equal("AWS S3", TakeoverFingerprints.ForCname("assets.acme.com.s3.amazonaws.com")?.Service);
        Assert.Null(TakeoverFingerprints.ForCname("www.example.com"));
    }

    /// <summary>
    /// Ελέγχει τους κανόνες για θύρες: βάσεις δεδομένων πάντα, απομακρυσμένη πρόσβαση μόνο από
    /// "medium" και πάνω (ένα σκέτο SSH δεν είναι από μόνο του εύρημα).
    /// </summary>
    [Fact]
    public void Correlations_PortRules()
    {
        ScanEvent Ev(long id, string type, string data, string? risk = null) => new(id, type, data, "port_scan", 1, risk, null, 2);
        var root = new ScanEvent(1, EventTypes.Domain, "example.com", "engine", null, null, null, 0);

        List<ScanEvent> sshOnly = [root, Ev(2, EventTypes.TcpPortOpen, "203.0.113.7:22 (SSH) · SSH-2.0-OpenSSH_9.6", "low")];
        Assert.Empty(CorrelationEngine.Run(sshOnly, [new Edge(1, 2)]));

        List<ScanEvent> exposed = [root,
            Ev(2, EventTypes.TcpPortOpen, "203.0.113.7:6379 (Redis)", "high"),
            Ev(3, EventTypes.TcpPortOpen, "203.0.113.7:3389 (RDP)", "high"),
            Ev(4, EventTypes.DnsIssue, $"{DnsIssues.ZoneTransfer} ns1.example.com: 42 records", "high")];
        var rules = CorrelationEngine.Run(exposed, [new Edge(1, 2), new Edge(1, 3), new Edge(1, 4)]).Select(c => c.RuleId).ToList();
        Assert.Contains("database_exposed", rules);
        Assert.Contains("remote_access_exposed", rules);
        Assert.Contains("zone_transfer", rules);
    }
}
