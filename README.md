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
| `blocklists` | passive | IP σε Spamhaus DROP και abuse.ch Feodo Tracker (έλεγχος τοπικά) |
| `wayback` | passive | Παλιά URLs: ξεχασμένα subdomains, backups, `.env`, admin panels |
| `github` | passive | Λογαριασμός και repos του οργανισμού → scan με Gitleaks Scanner |
| `ssl_cert` | footprint | Certificate: λήξη, hostname, εμπιστοσύνη, SANs |
| `http_fingerprint` | footprint | Web server, CMS/frameworks/CDN, security headers, redirects |
| `web_spider` | footprint | Σελίδες και **JavaScript**: secrets, emails, cloud buckets, σελίδες σύνδεσης |

- **Passive**: μόνο δημόσιες πηγές τρίτων. Ο στόχος δεν βλέπει τίποτα.
- **Footprint**: επιπλέον επισκέπτεται τα sites όπως ένας browser. Ζητά επιβεβαίωση ότι
  έχεις άδεια για τον στόχο.

## Εγκατάσταση και εκτέλεση

Χρειάζεσαι το [.NET 11 SDK](https://dotnet.microsoft.com/download):

```bash
dotnet run --project src/AttackSurfaceMapper.Api
```

Άνοιξε το http://localhost:5090.

**Προαιρετικά:**

- **GitHub token**: αν είσαι συνδεδεμένος με `gh auth login` (ή έχεις `GITHUB_TOKEN`), το όριο
  του GitHub API γίνεται 5000 αιτήματα την ώρα αντί για 60.
- **Gitleaks Scanner**: για να σκανάρονται τα repos για secrets, τρέξε το
  [gitleaks-scanner](https://github.com/fkalfopoulos/gitleaks-scanner) στη θύρα 5080. Άλλο URL
  ρυθμίζεται με το `GitleaksScanner:Url` στο `src/AttackSurfaceMapper.Api/appsettings.json`.

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

## Συσχετίσεις

Όταν τελειώσει ένα scan, κανόνες εξετάζουν τον **συνδυασμό** των ευρημάτων, όπως στο SpiderFoot.
Τα αποτελέσματα εμφανίζονται στην κορυφή της καρτέλας «Ευρήματα»:

| Κανόνας | Πότε ισχύει |
| --- | --- |
| Δημόσια διαθέσιμα secrets | Secrets σε repos ή σε JavaScript του site |
| Πιθανό subdomain takeover | CNAME προς υπηρεσία που δεν υπάρχει πια |
| Υποδομή σε blocklists | IP του στόχου σε Spamhaus/abuse.ch |
| Εύκολο email spoofing | Ούτε αποτελεσματικό SPF ούτε DMARC |
| Dev/test συστήματα στο Internet | `dev`, `staging`, `uat`… με δημόσια IP |
| Εσωτερικές IP σε δημόσιο DNS | 10.x, 192.168.x κ.λπ. σε δημόσια records |
| Προβλήματα certificates | Ληγμένα, μη έμπιστα ή λάθος certificates |
| Ευαίσθητα αρχεία στο Wayback | Backups, `.env`, βάσεις στο αρχείο του Internet |
| Πιθανά ξεχασμένα hosts | Hosts μόνο σε παλιά certificates, χωρίς DNS |
| Ασυνήθιστος πάροχος / χώρα | Μία IP σε πάροχο ή χώρα διαφορετική από όλες τις άλλες |

Οι κανόνες είναι C# κλάσεις στο `src/AttackSurfaceMapper.Domain/Correlations.cs` και ελέγχονται με tests.

## Αρχιτεκτονική

Clean Architecture: κάθε layer είναι ξεχωριστό project, οπότε ο compiler δεν επιτρέπει λάθος
εξαρτήσεις.

```
AttackSurfaceMapper.Api  ──►  AttackSurfaceMapper.Application  ──►  AttackSurfaceMapper.Domain
          │                              ▲
          └──►  AttackSurfaceMapper.Infrastructure (modules, SQLite, HTTP, DNS)
```

| Project | Περιεχόμενο |
| --- | --- |
| `src/AttackSurfaceMapper.Domain` | Τύποι events, scope, σύγκριση scans, κανόνες συσχέτισης, patterns για secrets και URLs: καθαρή λογική |
| `src/AttackSurfaceMapper.Application` | Η μηχανή των scans (`ScanRun`, `ScanManager`), το `IModule`, use cases (`ScanAppService`), interfaces |
| `src/AttackSurfaceMapper.Infrastructure` | Τα 11 modules, SQLite, προστασία SSRF (`NetGuard`), HTTP clients, γέφυρα προς το Gitleaks Scanner |
| `src/AttackSurfaceMapper.Api` | HTTP endpoints, UI (`wwwroot/`, γράφος με [Cytoscape.js](https://js.cytoscape.org)), logging |
| `tests/AttackSurfaceMapper.Tests` | Unit tests (xUnit) |

Για νέο module, φτιάξε κλάση που υλοποιεί το `IModule` στο `Infrastructure/Modules/` και πρόσθεσέ
τη στο `Infrastructure/DependencyInjection.cs`. Ό,τι χρειάζεται (DNS, HTTP) το παίρνει από τον
constructor. Κάθε method έχει XML documentation στα ελληνικά.

## Logging

[Serilog](https://serilog.net) με έξοδο στην κονσόλα και σε αρχείο ανά ημέρα στο
`src/AttackSurfaceMapper.Api/appdata/logs/` (κρατιούνται 14 ημέρες). Καταγράφονται η αρχή και
το τέλος κάθε scan, τα warnings και τα errors των modules (με το id του scan) και τα αιτήματα
που αλλάζουν κάτι. Τα secrets που βρίσκει ο spider αποθηκεύονται και καταγράφονται μόνο με απόκρυψη.

## Σύγκριση scans

Κάθε scan συγκρίνεται με το προηγούμενο ολοκληρωμένο scan του ίδιου στόχου, στο ίδιο επίπεδο.
Η καρτέλα **Αλλαγές** δείχνει τι **εμφανίστηκε**, π.χ. ένα subdomain που στήθηκε χθες, και τι
**εξαφανίστηκε**. Οι νέοι κόμβοι επισημαίνονται και στον γράφο.

## Tests

```bash
dotnet test AttackSurfaceMapper.slnx
```

Τα tests καλύπτουν το scope, την προστασία SSRF, τον έλεγχο του στόχου, τη σύγκριση scans,
τους κανόνες συσχέτισης, την αναγνώριση secrets/URLs και τη μηχανή με ψεύτικα modules (αλυσίδα events, dedupe, σφάλματα, ακύρωση), χωρίς
πρόσβαση στο δίκτυο. Τρέχουν αυτόματα σε κάθε push μέσω GitHub Actions.

## Άδεια

[MIT](LICENSE). Η αρχιτεκτονική είναι εμπνευσμένη από το SpiderFoot (MIT, © Steve Micallef).

## Επόμενα βήματα

- **Φάση 3**: ενεργά modules (DNS brute force, port scan, έλεγχος subdomain takeover), μόνο με
  ρητή εξουσιοδότηση.
