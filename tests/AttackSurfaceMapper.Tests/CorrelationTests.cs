using AttackSurfaceMapper.Domain;

namespace AttackSurfaceMapper.Tests;

/// <summary>Tests για τους κανόνες συσχέτισης.</summary>
public class CorrelationTests
{
    /// <summary>Βοηθός για την κατασκευή ενός μικρού γράφου events στα tests.</summary>
    sealed class Graph
    {
        /// <summary>Τα events.</summary>
        public List<ScanEvent> Events { get; } = [];
        /// <summary>Οι ακμές.</summary>
        public List<Edge> Edges { get; } = [];

        /// <summary>Δημιουργεί τον γράφο με τη ρίζα example.com (id 1).</summary>
        public Graph() => Events.Add(new ScanEvent(1, EventTypes.Domain, "example.com", "engine", null, null, null, 0));

        /// <summary>Προσθέτει ένα event κάτω από έναν γονέα.</summary>
        /// <param name="type">Ο τύπος.</param>
        /// <param name="data">Η τιμή.</param>
        /// <param name="parent">Ο γονέας.</param>
        /// <param name="module">Το module.</param>
        /// <param name="risk">Ο κίνδυνος.</param>
        /// <returns>Το id του νέου event.</returns>
        public long Add(string type, string data, long parent = 1, string module = "test", string? risk = null)
        {
            var id = Events.Count + 1;
            Events.Add(new ScanEvent(id, type, data, module, parent, risk, null, 1));
            Edges.Add(new Edge(parent, id));
            return id;
        }

        /// <summary>Προσθέτει επιπλέον ακμή (ένα event με δεύτερο γονέα).</summary>
        /// <param name="from">Ο γονέας.</param>
        /// <param name="to">Το παιδί.</param>
        public void Link(long from, long to) => Edges.Add(new Edge(from, to));

        /// <summary>Εκτελεί τους κανόνες.</summary>
        /// <returns>Τα ids των κανόνων που ισχύουν.</returns>
        public List<string> Rules() => CorrelationEngine.Run(Events, Edges).Select(c => c.RuleId).ToList();
    }

    /// <summary>Ελέγχει ότι χωρίς SPF και χωρίς DMARC βγαίνει "εύκολο spoofing", αλλά όχι με μόνο το ένα.</summary>
    [Fact]
    public void EmailSpoofing_RequiresBothSpfAndDmarcProblems()
    {
        var g = new Graph();
        g.Add(EventTypes.DnsIssue, DnsIssues.NoSpf);
        Assert.DoesNotContain("email_spoofing", g.Rules());

        g.Add(EventTypes.DnsIssue, DnsIssues.DmarcNone);
        Assert.Contains("email_spoofing", g.Rules());
    }

    /// <summary>Ελέγχει ότι αναφέρονται μόνο dev/test hosts που έχουν πραγματικά δημόσια IP.</summary>
    [Fact]
    public void DevTestExposed_OnlyForResolvingHosts()
    {
        var g = new Graph();
        g.Add(EventTypes.Host, "staging.example.com");                 // χωρίς IP
        g.Add(EventTypes.Host, "devices.example.com");                 // "dev" μόνο ως μέρος λέξης
        Assert.DoesNotContain("dev_test_exposed", g.Rules());

        var dev = g.Add(EventTypes.Host, "dev2.example.com");
        g.Add(EventTypes.Ip, "203.0.113.7", dev);
        var c = Assert.Single(CorrelationEngine.Run(g.Events, g.Edges), x => x.RuleId == "dev_test_exposed");
        Assert.Equal([dev], c.EventIds);
    }

    /// <summary>
    /// Ελέγχει ότι ένας πάροχος που εμφανίζεται σε μία μόνο από πολλές IP θεωρείται ασυνήθιστος,
    /// αλλά όχι όταν οι IP είναι λίγες.
    /// </summary>
    [Fact]
    public void OutlierHosting_FlagsRareProvider()
    {
        var g = new Graph();
        var aws = g.Add(EventTypes.Hosting, "Amazon Web Services");
        var hetzner = g.Add(EventTypes.Hosting, "Hetzner");
        // 10 IP στο AWS, 1 στη Hetzner
        for (var i = 0; i < 10; i++) g.Link(g.Add(EventTypes.Ip, $"198.51.100.{i}"), aws);
        g.Link(g.Add(EventTypes.Ip, "203.0.113.50"), hetzner);

        var c = Assert.Single(CorrelationEngine.Run(g.Events, g.Edges), x => x.RuleId == "outlier_hosting");
        Assert.Equal([hetzner], c.EventIds);
    }

    /// <summary>Ελέγχει ότι με λίγες IP δεν βγαίνουν συμπεράσματα για "ασυνήθιστο" πάροχο.</summary>
    [Fact]
    public void OutlierHosting_NeedsEnoughData()
    {
        var g = new Graph();
        var a = g.Add(EventTypes.Hosting, "A");
        var b = g.Add(EventTypes.Hosting, "B");
        g.Link(g.Add(EventTypes.Ip, "198.51.100.1"), a);
        g.Link(g.Add(EventTypes.Ip, "198.51.100.2"), a);
        g.Link(g.Add(EventTypes.Ip, "203.0.113.1"), b);
        Assert.DoesNotContain("outlier_hosting", g.Rules());
    }

    /// <summary>Ελέγχει ότι "ξεχασμένα" θεωρούνται hosts που ήρθαν από certificates και δεν έχουν DNS.</summary>
    [Fact]
    public void ForgottenHosts_FromCertificatesWithoutDns()
    {
        var g = new Graph();
        var host = g.Add(EventTypes.Host, "old.example.com", module: "cert_transparency");
        g.Add(EventTypes.HostUnresolved, "old.example.com", host);
        var other = g.Add(EventTypes.Host, "x.example.com", module: "wayback");
        g.Add(EventTypes.HostUnresolved, "x.example.com", other);

        var c = Assert.Single(CorrelationEngine.Run(g.Events, g.Edges), x => x.RuleId == "forgotten_hosts");
        Assert.Single(c.EventIds);
    }

    /// <summary>Ελέγχει ότι τα secrets σε repos μετράνε μόνο όταν βρέθηκαν πραγματικά (όχι τα "καθαρά" repos).</summary>
    [Fact]
    public void SecretsExposed_IgnoresCleanRepos()
    {
        var g = new Graph();
        g.Add(EventTypes.LeakedSecrets, "repo: καθαρό", risk: "info");
        Assert.DoesNotContain("secrets_exposed", g.Rules());
        g.Add(EventTypes.SecretInContent, "AWS Access Key ••••••MPLQ στο https://example.com/app.js", risk: "high");
        Assert.Contains("secrets_exposed", g.Rules());
    }

    /// <summary>Ελέγχει ότι τα αποτελέσματα ταξινομούνται από τον υψηλότερο κίνδυνο.</summary>
    [Fact]
    public void Run_SortsByRisk()
    {
        var g = new Graph();
        g.Add(EventTypes.InternalIp, "10.0.0.5");                         // medium
        g.Add(EventTypes.Takeover, "a.example.com → x.herokuapp.com");    // high
        var risks = CorrelationEngine.Run(g.Events, g.Edges).Select(c => c.Risk).ToList();
        Assert.Equal(["high", "medium"], risks);
    }
}
