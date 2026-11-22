namespace AttackSurfaceMapper.Domain;

/// <summary>Η κατηγορία μιας υπηρεσίας, για τους κανόνες συσχέτισης.</summary>
public enum PortCategory
{
    /// <summary>Web (HTTP/HTTPS).</summary>
    Web,
    /// <summary>Βάση δεδομένων ή cache (δεν πρέπει ποτέ να είναι δημόσια).</summary>
    Database,
    /// <summary>Απομακρυσμένη πρόσβαση (RDP, VNC, SSH, Telnet).</summary>
    RemoteAccess,
    /// <summary>Διαχείριση υποδομής (Docker, Kubernetes, Elasticsearch κ.λπ.).</summary>
    Management,
    /// <summary>Αρχεία (FTP, SMB, NFS).</summary>
    FileSharing,
    /// <summary>Email.</summary>
    Mail,
    /// <summary>Άλλο.</summary>
    Other,
}

/// <summary>Μια θύρα TCP και τι σημαίνει αν είναι ανοιχτή στο Internet.</summary>
/// <param name="Port">Ο αριθμός της θύρας.</param>
/// <param name="Service">Η συνηθισμένη υπηρεσία.</param>
/// <param name="Category">Η κατηγορία.</param>
/// <param name="Risk">Ο κίνδυνος αν είναι ανοιχτή στο Internet.</param>
public record PortInfo(int Port, string Service, PortCategory Category, string Risk);

/// <summary>
/// Οι θύρες που ελέγχει το port scan: όχι όλες (65535), αλλά αυτές που, αν είναι ανοιχτές στο
/// Internet, συνήθως σημαίνουν πρόβλημα ή αποκαλύπτουν σημαντική υποδομή.
/// </summary>
public static class PortCatalog
{
    /// <summary>Όλες οι θύρες που ελέγχονται.</summary>
    public static readonly IReadOnlyList<PortInfo> All =
    [
        new(21, "FTP", PortCategory.FileSharing, "medium"),
        new(22, "SSH", PortCategory.RemoteAccess, "low"),
        new(23, "Telnet", PortCategory.RemoteAccess, "high"),
        new(25, "SMTP", PortCategory.Mail, "info"),
        new(53, "DNS", PortCategory.Other, "info"),
        new(80, "HTTP", PortCategory.Web, "info"),
        new(110, "POP3", PortCategory.Mail, "low"),
        new(111, "RPC portmapper", PortCategory.Other, "medium"),
        new(135, "MS RPC", PortCategory.Other, "high"),
        new(139, "NetBIOS", PortCategory.FileSharing, "high"),
        new(143, "IMAP", PortCategory.Mail, "low"),
        new(389, "LDAP", PortCategory.Management, "high"),
        new(443, "HTTPS", PortCategory.Web, "info"),
        new(445, "SMB", PortCategory.FileSharing, "high"),
        new(465, "SMTPS", PortCategory.Mail, "info"),
        new(587, "SMTP submission", PortCategory.Mail, "info"),
        new(993, "IMAPS", PortCategory.Mail, "info"),
        new(995, "POP3S", PortCategory.Mail, "info"),
        new(1433, "Microsoft SQL Server", PortCategory.Database, "high"),
        new(1521, "Oracle DB", PortCategory.Database, "high"),
        new(2049, "NFS", PortCategory.FileSharing, "high"),
        new(2375, "Docker API (χωρίς TLS)", PortCategory.Management, "high"),
        new(2376, "Docker API", PortCategory.Management, "medium"),
        new(3000, "Dev server / Grafana", PortCategory.Web, "low"),
        new(3306, "MySQL", PortCategory.Database, "high"),
        new(3389, "RDP", PortCategory.RemoteAccess, "high"),
        new(5000, "Dev server / Docker registry", PortCategory.Web, "low"),
        new(5432, "PostgreSQL", PortCategory.Database, "high"),
        new(5601, "Kibana", PortCategory.Management, "medium"),
        new(5672, "RabbitMQ", PortCategory.Management, "medium"),
        new(5900, "VNC", PortCategory.RemoteAccess, "high"),
        new(5984, "CouchDB", PortCategory.Database, "high"),
        new(6379, "Redis", PortCategory.Database, "high"),
        new(6443, "Kubernetes API", PortCategory.Management, "high"),
        new(8000, "HTTP (alt)", PortCategory.Web, "low"),
        new(8080, "HTTP proxy / alt", PortCategory.Web, "low"),
        new(8443, "HTTPS (alt)", PortCategory.Web, "low"),
        new(8888, "HTTP (alt) / Jupyter", PortCategory.Web, "low"),
        new(9000, "PHP-FPM / SonarQube / MinIO", PortCategory.Management, "medium"),
        new(9042, "Cassandra", PortCategory.Database, "high"),
        new(9090, "Prometheus / admin", PortCategory.Management, "medium"),
        new(9200, "Elasticsearch", PortCategory.Database, "high"),
        new(10250, "Kubelet", PortCategory.Management, "high"),
        new(11211, "Memcached", PortCategory.Database, "high"),
        new(27017, "MongoDB", PortCategory.Database, "high"),
    ];

    static readonly Dictionary<int, PortInfo> ByPort = All.ToDictionary(p => p.Port);

    /// <summary>Επιστρέφει τις πληροφορίες μιας θύρας.</summary>
    /// <param name="port">Η θύρα.</param>
    /// <returns>Οι πληροφορίες, ή μια γενική εγγραφή για άγνωστη θύρα.</returns>
    public static PortInfo Get(int port) =>
        ByPort.TryGetValue(port, out var info) ? info : new PortInfo(port, "άγνωστη", PortCategory.Other, "low");

    /// <summary>
    /// Φτιάχνει την τιμή ενός event ανοιχτής θύρας, π.χ. "203.0.113.7:3306 (MySQL)" ή, για IPv6,
    /// "[2001:db8::1]:22 (SSH)" (με αγκύλες, όπως στα URLs, για να μη μπερδεύεται η θύρα με τη διεύθυνση).
    /// Η μορφή είναι σταθερή ώστε να τη διαβάζουν οι κανόνες με τη <see cref="TryParse"/>.
    /// </summary>
    /// <param name="ip">Η IP.</param>
    /// <param name="port">Η θύρα.</param>
    /// <param name="banner">Το banner της υπηρεσίας, αν διαβάστηκε.</param>
    /// <returns>Η τιμή.</returns>
    public static string Format(string ip, int port, string? banner) =>
        $"{(ip.Contains(':') ? $"[{ip}]" : ip)}:{port} ({Get(port).Service})" + (string.IsNullOrWhiteSpace(banner) ? "" : $" · {banner}");

    /// <summary>Διαβάζει τη θύρα από την τιμή ενός event ανοιχτής θύρας.</summary>
    /// <param name="data">Η τιμή (βλ. <see cref="Format"/>).</param>
    /// <param name="info">Οι πληροφορίες της θύρας.</param>
    /// <returns><c>true</c> αν διαβάστηκε.</returns>
    public static bool TryParse(string data, out PortInfo info)
    {
        info = default!;
        var head = data.Split(' ')[0];
        var colon = head.LastIndexOf(':');
        if (colon < 0 || !int.TryParse(head[(colon + 1)..], out var port)) return false;
        info = Get(port);
        return true;
    }
}
