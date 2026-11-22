namespace AttackSurfaceMapper.Domain;

/// <summary>
/// Οι τύποι δεδομένων που ανταλλάσσουν τα modules μεταξύ τους.
/// </summary>
/// <remarks>
/// Τα ονόματα ακολουθούν τη σύμβαση του SpiderFoot (MIT). Κάθε module δηλώνει ποιους τύπους
/// παρακολουθεί και ποιους παράγει, και η μηχανή τα συνδέει μέσω αυτών.
/// Η ελληνική περιγραφή κάθε σταθεράς βρίσκεται στο <see cref="Meta"/>.
/// </remarks>
public static class EventTypes
{
#pragma warning disable CS1591 // Οι σταθερές περιγράφονται στο Meta παρακάτω.
    public const string Domain = "DOMAIN_NAME";
    public const string Host = "INTERNET_NAME";
    public const string AffiliateHost = "AFFILIATE_INTERNET_NAME";
    public const string HostUnresolved = "INTERNET_NAME_UNRESOLVED";
    public const string Ip = "IP_ADDRESS";
    public const string Ip6 = "IPV6_ADDRESS";
    public const string InternalIp = "INTERNAL_IP_ADDRESS";
    public const string Asn = "BGP_AS_OWNER";
    public const string Netblock = "NETBLOCK_MEMBER";
    public const string Geo = "GEOINFO";
    public const string Hosting = "PROVIDER_HOSTING";
    public const string DnsProvider = "PROVIDER_DNS";
    public const string MailProvider = "PROVIDER_MAIL";
    public const string DnsText = "DNS_TEXT";
    public const string Spf = "DNS_SPF";
    public const string Dmarc = "DNS_DMARC";
    public const string DnsIssue = "DNS_ISSUE";
    public const string Takeover = "SUBDOMAIN_TAKEOVER_CANDIDATE";
    public const string Saas = "SAAS_SERVICE";
    public const string Registrar = "DOMAIN_REGISTRAR";
    public const string DomainDates = "DOMAIN_WHOIS";
    public const string Email = "EMAILADDR";
    public const string CertIssuer = "SSL_CERTIFICATE_ISSUER";
    public const string CertExpired = "SSL_CERTIFICATE_EXPIRED";
    public const string CertExpiring = "SSL_CERTIFICATE_EXPIRING";
    public const string CertMismatch = "SSL_CERTIFICATE_MISMATCH";
    public const string CertUntrusted = "SSL_CERTIFICATE_UNTRUSTED";
    public const string Url = "WEB_URL";
    public const string NoTls = "HTTP_NO_TLS";
    public const string WebServer = "WEBSERVER_BANNER";
    public const string WebTech = "WEBSERVER_TECHNOLOGY";
    public const string MissingHeaders = "WEBSERVER_SECURITY_HEADERS_MISSING";
    public const string CodeRepoOwner = "CODE_REPOSITORY_OWNER";
    public const string CodeRepo = "CODE_REPOSITORY";
    public const string LeakedSecrets = "LEAKED_SECRETS";
    // Φάση 2
    public const string JsFile = "WEB_JAVASCRIPT";
    public const string LoginPage = "WEB_LOGIN_PAGE";
    public const string CloudBucket = "CLOUD_STORAGE_BUCKET";
    public const string SecretInContent = "SECRET_IN_CONTENT";
    public const string HistoricUrl = "HISTORIC_URL";
    public const string Malicious = "MALICIOUS_ASSET";
#pragma warning restore CS1591

    /// <summary>Πληροφορίες εμφάνισης ενός τύπου event στο UI.</summary>
    /// <param name="Label">Η ελληνική ετικέτα του τύπου.</param>
    /// <param name="Group">Η ομάδα του τύπου, που καθορίζει το χρώμα του στον γράφο.</param>
    public record TypeInfo(string Label, string Group);

    /// <summary>Η ελληνική ετικέτα και η ομάδα κάθε τύπου event.</summary>
    public static readonly IReadOnlyDictionary<string, TypeInfo> Meta = new Dictionary<string, TypeInfo>
    {
        [Domain] = new("Domain (στόχος)", "target"),
        [Host] = new("Hostname", "host"),
        [AffiliateHost] = new("Συνδεδεμένο hostname (εκτός scope)", "affiliate"),
        [HostUnresolved] = new("Hostname χωρίς DNS", "host"),
        [Ip] = new("IPv4", "network"),
        [Ip6] = new("IPv6", "network"),
        [InternalIp] = new("Εσωτερική IP σε δημόσιο DNS", "network"),
        [Asn] = new("ASN", "network"),
        [Netblock] = new("Netblock", "network"),
        [Geo] = new("Χώρα", "network"),
        [Hosting] = new("Hosting / Cloud", "network"),
        [DnsProvider] = new("DNS provider (NS)", "dns"),
        [MailProvider] = new("Mail server (MX)", "dns"),
        [DnsText] = new("TXT record", "dns"),
        [Spf] = new("SPF", "dns"),
        [Dmarc] = new("DMARC", "dns"),
        [DnsIssue] = new("Πρόβλημα DNS / email", "dns"),
        [Takeover] = new("Πιθανό subdomain takeover", "dns"),
        [Saas] = new("SaaS υπηρεσία", "dns"),
        [Registrar] = new("Registrar", "registry"),
        [DomainDates] = new("Καταχώριση domain", "registry"),
        [Email] = new("Email", "people"),
        [CertIssuer] = new("Εκδότης certificate", "cert"),
        [CertExpired] = new("Ληγμένο certificate", "cert"),
        [CertExpiring] = new("Certificate λήγει σύντομα", "cert"),
        [CertMismatch] = new("Certificate για άλλο host", "cert"),
        [CertUntrusted] = new("Μη έμπιστο certificate", "cert"),
        [Url] = new("Web URL", "web"),
        [NoTls] = new("Χωρίς HTTPS", "web"),
        [WebServer] = new("Web server", "web"),
        [WebTech] = new("Τεχνολογία", "web"),
        [MissingHeaders] = new("Λείπουν security headers", "web"),
        [CodeRepoOwner] = new("GitHub οργανισμός", "code"),
        [CodeRepo] = new("Repository", "code"),
        [LeakedSecrets] = new("Secrets σε repository", "code"),
        [JsFile] = new("JavaScript αρχείο", "web"),
        [LoginPage] = new("Σελίδα σύνδεσης", "web"),
        [CloudBucket] = new("Cloud storage bucket", "web"),
        [SecretInContent] = new("Secret σε σελίδα / JavaScript", "code"),
        [HistoricUrl] = new("Ευαίσθητο παλιό URL (Wayback)", "web"),
        [Malicious] = new("Σε blocklist", "network"),
    };

    /// <summary>Τα επίπεδα κινδύνου ενός ευρήματος, από το χαμηλότερο στο υψηλότερο.</summary>
    public static readonly string[] Risks = ["info", "low", "medium", "high"];
}
