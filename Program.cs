using AttackSurfaceMapper;
using AttackSurfaceMapper.Data;
using AttackSurfaceMapper.Engine;
using AttackSurfaceMapper.Modules;
using DnsClient;

var builder = WebApplication.CreateBuilder(args);

// Ακούμε ΜΟΝΟ στο localhost, και δεχόμαστε μόνο αιτήματα με Host "localhost": αλλιώς μια
// κακόβουλη ιστοσελίδα θα μπορούσε, με DNS rebinding, να ξεκινά scans μέσω του browser σου.
builder.WebHost.UseUrls("http://localhost:5090");
builder.Configuration["AllowedHosts"] = "localhost";

var dataDir = Path.Combine(builder.Environment.ContentRootPath, "data");
Directory.CreateDirectory(dataDir);
var store = new Store(Path.Combine(dataDir, "surface.db"));
store.Init();
builder.Services.AddSingleton(store);

builder.Services.AddSingleton<ILookupClient>(_ => new LookupClient(new LookupClientOptions
{
    UseCache = true,
    Timeout = TimeSpan.FromSeconds(5),
    Retries = 2,
    ThrowDnsErrors = false,
}));

// Τα modules. Για να προσθέσεις νέο: φτιάξε κλάση που υλοποιεί το IModule και πρόσθεσέ την εδώ.
builder.Services.AddSingleton<IModule, DnsResolveModule>();
builder.Services.AddSingleton<IModule, DnsRecordsModule>();
builder.Services.AddSingleton<IModule, CertTransparencyModule>();
builder.Services.AddSingleton<IModule, RdapModule>();
builder.Services.AddSingleton<IModule, IpInfoModule>();
builder.Services.AddSingleton<IModule, GitHubModule>();
builder.Services.AddSingleton<IModule, SslCertModule>();
builder.Services.AddSingleton<IModule, HttpFingerprintModule>();
builder.Services.AddSingleton<ScanManager>();

const string userAgent = "Mozilla/5.0 (compatible; AttackSurfaceMapper/1.0)";

builder.Services.AddHttpClient(HttpClients.External, c =>
{
    c.DefaultRequestHeaders.UserAgent.ParseAdd(userAgent);
    c.Timeout = TimeSpan.FromSeconds(90);   // το crt.sh είναι συχνά αργό
});

builder.Services.AddHttpClient(HttpClients.Target, c =>
{
    c.DefaultRequestHeaders.UserAgent.ParseAdd(userAgent);
    c.Timeout = TimeSpan.FromSeconds(20);
}).ConfigurePrimaryHttpMessageHandler(NetGuard.CreateHandler);

var githubToken = GitHubToken.Resolve();
builder.Services.AddHttpClient(HttpClients.GitHub, c =>
{
    c.BaseAddress = new Uri("https://api.github.com/");
    c.DefaultRequestHeaders.UserAgent.ParseAdd("attack-surface-mapper/1.0");
    c.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
    if (githubToken is not null) c.DefaultRequestHeaders.Authorization = new("Bearer", githubToken);
    c.Timeout = TimeSpan.FromSeconds(30);
});

builder.Services.AddHttpClient(HttpClients.Gitleaks, c =>
{
    c.BaseAddress = new Uri(builder.Configuration["GitleaksScanner:Url"] ?? "http://localhost:5080/");
    c.Timeout = TimeSpan.FromMinutes(20);   // ένα μεγάλο repo με όλο το ιστορικό θέλει χρόνο
});

var app = builder.Build();
app.Logger.LogInformation("GitHub API: {Mode}", githubToken is null
    ? "χωρίς token (60 αιτήματα/ώρα)" : "με token (5000 αιτήματα/ώρα)");

app.UseDefaultFiles();
app.UseStaticFiles();
app.MapApi();
app.Run();
