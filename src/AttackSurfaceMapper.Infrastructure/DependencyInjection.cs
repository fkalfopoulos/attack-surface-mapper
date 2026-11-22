using AttackSurfaceMapper.Application.Abstractions;
using AttackSurfaceMapper.Infrastructure.Modules;
using AttackSurfaceMapper.Infrastructure.Modules.Active;
using AttackSurfaceMapper.Infrastructure.Network;
using AttackSurfaceMapper.Infrastructure.Persistence;
using DnsClient;
using Microsoft.Extensions.DependencyInjection;

namespace AttackSurfaceMapper.Infrastructure;

/// <summary>Οι ρυθμίσεις της Infrastructure.</summary>
/// <param name="DataDirectory">Ο φάκελος για τη βάση (δεν πρέπει να μπει ποτέ στο git).</param>
/// <param name="GitleaksScannerUrl">Η διεύθυνση του Gitleaks Scanner.</param>
public record InfrastructureOptions(string DataDirectory, Uri GitleaksScannerUrl);

/// <summary>Καταχώριση των υλοποιήσεων της Infrastructure στο dependency injection.</summary>
public static class DependencyInjection
{
    const string UserAgent = "Mozilla/5.0 (compatible; AttackSurfaceMapper/1.0)";

    /// <summary>
    /// Καταχωρεί τη βάση SQLite, τον DNS client, όλα τα modules, τους HTTP clients και τη γέφυρα
    /// προς το Gitleaks Scanner.
    /// </summary>
    /// <param name="services">Η συλλογή υπηρεσιών.</param>
    /// <param name="options">Οι ρυθμίσεις.</param>
    /// <returns>Την ίδια συλλογή, για αλυσιδωτές κλήσεις.</returns>
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, InfrastructureOptions options)
    {
        Directory.CreateDirectory(options.DataDirectory);
        var store = new SqliteScanStore(Path.Combine(options.DataDirectory, "surface.db"));
        store.Init();
        services.AddSingleton<IScanStore>(store);

        services.AddSingleton<ILookupClient>(_ => new LookupClient(new LookupClientOptions
        {
            UseCache = true,
            Timeout = TimeSpan.FromSeconds(5),
            Retries = 2,
            ThrowDnsErrors = false,
        }));

        // Τα modules. Για νέο module: κλάση που υλοποιεί το IModule, και μια γραμμή εδώ.
        services.AddSingleton<IModule, DnsResolveModule>();
        services.AddSingleton<IModule, DnsRecordsModule>();
        services.AddSingleton<IModule, CertTransparencyModule>();
        services.AddSingleton<IModule, RdapModule>();
        services.AddSingleton<IModule, IpInfoModule>();
        services.AddSingleton<IModule, BlocklistModule>();
        services.AddSingleton<IModule, WaybackModule>();
        services.AddSingleton<IModule, GitHubModule>();
        services.AddSingleton<IModule, SslCertModule>();
        services.AddSingleton<IModule, HttpFingerprintModule>();
        services.AddSingleton<IModule, WebSpiderModule>();

        // Φάση 3: ενεργά modules (τρέχουν μόνο σε active scan, με ρητή εξουσιοδότηση).
        services.AddSingleton(PortScanner.Public);
        services.AddSingleton<IModule, DnsBruteforceModule>();
        services.AddSingleton<IModule, ZoneTransferModule>();
        services.AddSingleton<IModule, PortScanModule>();
        services.AddSingleton<IModule, TakeoverVerifyModule>();

        services.AddSingleton<IGitleaksScannerClient, GitleaksScannerClient>();
        AddHttpClients(services, options);
        return services;
    }

    /// <summary>
    /// Ρυθμίζει τους HTTP clients: για τρίτους, για τον στόχο (με προστασία SSRF), για το GitHub
    /// (με token αν υπάρχει) και για το Gitleaks Scanner.
    /// </summary>
    /// <param name="services">Η συλλογή υπηρεσιών.</param>
    /// <param name="options">Οι ρυθμίσεις.</param>
    static void AddHttpClients(IServiceCollection services, InfrastructureOptions options)
    {
        services.AddHttpClient(HttpClients.External, c =>
        {
            c.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
            c.Timeout = TimeSpan.FromSeconds(120);   // το crt.sh και το Wayback είναι συχνά αργά
        });

        services.AddHttpClient(HttpClients.Target, c =>
        {
            c.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
            c.Timeout = TimeSpan.FromSeconds(20);
        }).ConfigurePrimaryHttpMessageHandler(NetGuard.CreateHandler);

        var githubToken = GitHubToken.Resolve();
        services.AddHttpClient(HttpClients.GitHub, c =>
        {
            c.BaseAddress = new Uri("https://api.github.com/");
            c.DefaultRequestHeaders.UserAgent.ParseAdd("attack-surface-mapper/1.0");
            c.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
            if (githubToken is not null) c.DefaultRequestHeaders.Authorization = new("Bearer", githubToken);
            c.Timeout = TimeSpan.FromSeconds(30);
        });

        services.AddHttpClient(HttpClients.Gitleaks, c =>
        {
            c.BaseAddress = options.GitleaksScannerUrl;
            c.Timeout = TimeSpan.FromMinutes(20);   // ένα μεγάλο repo με όλο το ιστορικό θέλει χρόνο
        });
    }

    /// <summary>Αν βρέθηκε GitHub token (από <c>GITHUB_TOKEN</c> ή <c>gh auth token</c>).</summary>
    /// <returns><c>true</c> αν υπάρχει token.</returns>
    public static bool HasGitHubToken() => GitHubToken.Resolve() is not null;
}
