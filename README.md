# 🛰️ Attack Surface Mapper

[![CI](https://github.com/fkalfopoulos/attack-surface-mapper/actions/workflows/ci.yml/badge.svg)](https://github.com/fkalfopoulos/attack-surface-mapper/actions/workflows/ci.yml)

Τοπικό web app (ASP.NET Core / C#) για **OSINT** και **χαρτογράφηση του attack surface** ενός
domain. Δίνεις ένα domain και το app βρίσκει subdomains, IPs, δίκτυα, certificates, τεχνολογίες,
SaaS υπηρεσίες και GitHub repos, και τα δείχνει σε **γράφο** που εξηγεί πώς βρέθηκε το καθένα.

Η αρχιτεκτονική είναι εμπνευσμένη από το [SpiderFoot](https://github.com/smicallef/spiderfoot)
(MIT, © Steve Micallef): modules που παρακολουθούν και παράγουν events, και τροφοδοτούν το
ένα το άλλο. Ο κώδικας είναι γραμμένος από την αρχή σε C#.

## Πώς δουλεύει

```
example.com ──dns_records──► MX, NS, SPF, DMARC, SaaS (Google Workspace, Microsoft 365…)
     │
     ├──cert_transparency──► api.example.com, dev.example.com, …
     │                            │
     │                            ├──dns_resolve──► 203.0.113.7 ──ip_info──► AS64500, Χώρα, Cloud
     │                            ├──ssl_cert─────► Certificate, λήξη, νέα hostnames (SANs)
     │                            └──http_fingerprint──► nginx/1.18, WordPress, security headers
     │
     └──github──► github.com/example ──► repos ──► Gitleaks Scanner ──► secrets
```

Κάθε module δηλώνει ποιους τύπους δεδομένων **παρακολουθεί** και ποιους **παράγει**. Η μηχανή
(`Engine/ScanEngine.cs`) στέλνει κάθε νέο εύρημα σε όσα modules το ενδιαφέρουν, μέχρι να μην
υπάρχει τίποτα καινούριο.

## Modules

| Module | Επίπεδο | Τι κάνει |
| --- | --- | --- |
| `dns_resolve` | passive | IPv4/IPv6, CNAME, πιθανά **subdomain takeovers** |
| `dns_records` | passive | MX, NS, TXT, έλεγχος **SPF / DMARC**, αναγνώριση SaaS |
| `cert_transparency` | passive | Subdomains από crt.sh (εφεδρεία: Cert Spotter) |
| `rdap` | passive | Registrar, ημερομηνίες λήξης, emails (RDAP / WHOIS) |
| `ip_info` | passive | ASN, netblock, χώρα, πάροχος cloud (RIPEstat) |
| `github` | passive | Λογαριασμός και repos του οργανισμού → scan με Gitleaks Scanner |
| `ssl_cert` | footprint | Certificate: λήξη, hostname, εμπιστοσύνη, SANs |
| `http_fingerprint` | footprint | Web server, CMS/frameworks/CDN, security headers, redirects |

- **Passive**: μόνο δημόσιες πηγές τρίτων. Ο στόχος δεν βλέπει τίποτα.
- **Footprint**: επιπλέον επισκέπτεται τα sites όπως ένας browser. Ζητά επιβεβαίωση ότι
  έχεις άδεια για τον στόχο.

## Εγκατάσταση και εκτέλεση

Χρειάζεσαι το [.NET 11 SDK](https://dotnet.microsoft.com/download):

```bash
dotnet run
```

Άνοιξε το http://localhost:5090.

**Προαιρετικά:**

- **GitHub token**: αν είσαι συνδεδεμένος με `gh auth login` (ή έχεις `GITHUB_TOKEN`), το όριο
  του GitHub API γίνεται 5000 αιτήματα την ώρα αντί για 60.
- **Gitleaks Scanner**: για να σκανάρονται τα repos για secrets, τρέξε το
  [gitleaks-scanner](https://github.com/fkalfopoulos/gitleaks-scanner) στη θύρα 5080. Άλλο URL
  ρυθμίζεται με το `GitleaksScanner:Url` στο `appsettings.json`.

## Ασφάλεια

- Ακούει **μόνο στο localhost** και απορρίπτει αιτήματα με άλλο `Host` header (DNS rebinding).
- **Προστασία SSRF**: δεν συνδέεται ποτέ σε ιδιωτικές IP (127.x, 10.x, 192.168.x,
  169.254.169.254 κ.λπ.), ακόμα κι αν ένα domain δείχνει εκεί. Ο έλεγχος γίνεται στην IP της
  πραγματικής σύνδεσης (`Engine/NetGuard.cs`).
- **Scope**: εξερευνά μόνο το domain και τα subdomains του. Hostnames άλλων domains
  καταγράφονται, αλλά δεν σκανάρονται.
- **Όρια**: 5000 events ανά scan, 150 hosts ανά footprint module, 1 ώρα ανά scan.
- Ένας λογαριασμός GitHub θεωρείται ότι ανήκει στον στόχο μόνο αν το προφίλ του αναφέρει το domain.

Χρησιμοποίησέ το μόνο σε domains που σου ανήκουν ή για τα οποία έχεις άδεια.

## Δομή

| Φάκελος / αρχείο | Περιεχόμενο |
| --- | --- |
| `Engine/` | Η μηχανή events, τύποι, scope, προστασία δικτύου |
| `Modules/` | Τα modules συλλογής πληροφοριών |
| `Data/Store.cs` | SQLite: scans, events, ακμές γράφου, logs |
| `Api.cs` | Τα HTTP endpoints |
| `wwwroot/` | Το UI (γράφος με [Cytoscape.js](https://js.cytoscape.org)) |

| `Data/ScanDiff.cs` | Σύγκριση με το προηγούμενο scan (νέα / εξαφανισμένα) |
| `tests/` | Unit tests (xUnit) |

Για νέο module, φτιάξε κλάση που υλοποιεί το `IModule` και πρόσθεσέ τη στο `Program.cs`.
Κάθε method έχει XML documentation στα ελληνικά.

## Σύγκριση scans

Κάθε scan συγκρίνεται με το προηγούμενο ολοκληρωμένο scan του ίδιου στόχου, στο ίδιο επίπεδο.
Η καρτέλα **Αλλαγές** δείχνει τι **εμφανίστηκε**, π.χ. ένα subdomain που στήθηκε χθες, και τι
**εξαφανίστηκε**. Οι νέοι κόμβοι επισημαίνονται και στον γράφο.

## Tests

```bash
dotnet test tests/AttackSurfaceMapper.Tests
```

Τα tests καλύπτουν το scope, την προστασία SSRF, τον έλεγχο του στόχου, τη σύγκριση scans
και τη μηχανή με ψεύτικα modules (αλυσίδα events, dedupe, σφάλματα, ακύρωση), χωρίς
πρόσβαση στο δίκτυο. Τρέχουν αυτόματα σε κάθε push μέσω GitHub Actions.

## Άδεια

[MIT](LICENSE). Η αρχιτεκτονική είναι εμπνευσμένη από το SpiderFoot (MIT, © Steve Micallef).

## Επόμενα βήματα

- **Φάση 2**: web spider, ανάλυση περιεχομένου (emails, κλειδιά), Wayback Machine, blocklists,
  κανόνες συσχέτισης.
- **Φάση 3**: ενεργά modules (DNS brute force, port scan, έλεγχος subdomain takeover), μόνο με
  ρητή εξουσιοδότηση.
