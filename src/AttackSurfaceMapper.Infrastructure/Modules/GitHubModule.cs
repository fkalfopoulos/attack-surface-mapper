using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AttackSurfaceMapper.Application.Abstractions;
using AttackSurfaceMapper.Application.Engine;
using AttackSurfaceMapper.Domain;
using AttackSurfaceMapper.Infrastructure.Network;

namespace AttackSurfaceMapper.Infrastructure.Modules;

/// <summary>
/// Βρίσκει τον λογαριασμό GitHub του οργανισμού και τα δημόσια repos του, και (αν το ζητήσει
/// ο χρήστης) τα σκανάρει για secrets μέσω του Gitleaks Scanner.
/// </summary>
/// <remarks>
/// Ο λογαριασμός θεωρείται ότι ανήκει στον στόχο ΜΟΝΟ αν το πεδίο "blog" ή "email" του προφίλ
/// δείχνει στο domain. Αλλιώς, ένα scan του acme.com θα σκάναρε τα repos ενός άσχετου χρήστη
/// με username "acme".
/// </remarks>
/// <param name="http">Το factory των HTTP clients.</param>
/// <param name="gitleaks">Η γέφυρα προς το Gitleaks Scanner.</param>
public sealed class GitHubModule(IHttpClientFactory http, IGitleaksScannerClient gitleaks) : IModule
{
    /// <summary>Πόσα repos εμφανίζονται το πολύ.</summary>
    const int MaxRepos = 50;

    /// <summary>Πόσα repos σκανάρονται το πολύ με το Gitleaks Scanner σε κάθε scan.</summary>
    const int MaxGitleaksScans = 10;

    /// <inheritdoc/>
    public string Name => "github";
    /// <inheritdoc/>
    public string Description => "Λογαριασμός GitHub και δημόσια repos του οργανισμού· προαιρετικά scan για secrets με το Gitleaks Scanner.";
    /// <inheritdoc/>
    public Footprint Level => Footprint.Passive;
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Watched { get; } = [EventTypes.Domain];
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Produced { get; } =
        [EventTypes.CodeRepoOwner, EventTypes.CodeRepo, EventTypes.LeakedSecrets];

    /// <summary>
    /// Ψάχνει λογαριασμό GitHub με το όνομα του οργανισμού, επιβεβαιώνει ότι ανήκει στο domain,
    /// εκπέμπει τα repos του και, αν είναι ενεργή η επιλογή, τα στέλνει στο Gitleaks Scanner.
    /// </summary>
    /// <param name="e">Το domain-στόχος.</param>
    /// <param name="ctx">Το context του scan.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Ένα task που ολοκληρώνεται όταν τελειώσουν η αναζήτηση και τα scans.</returns>
    public async Task HandleAsync(ScanEvent e, ScanContext ctx, CancellationToken ct)
    {
        var label = Scope.OrgLabel(e.Data);
        using var res = await http.CreateClient(HttpClients.GitHub).GetAsync($"users/{Uri.EscapeDataString(label)}", ct);
        if (res.StatusCode == HttpStatusCode.NotFound)
        {
            ctx.Log($"Δεν υπάρχει λογαριασμός GitHub με όνομα \"{label}\".");
            return;
        }
        if (!EnsureOk(res, ctx)) return;

        using var profile = await JsonDocument.ParseAsync(await res.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
        var login = profile.RootElement.GetProperty("login").GetString()!;
        var htmlUrl = profile.RootElement.GetProperty("html_url").GetString();

        if (!BelongsToDomain(profile.RootElement, e.Data))
        {
            ctx.Emit(EventTypes.CodeRepoOwner, $"github.com/{login} (μη επιβεβαιωμένο)", e, link: htmlUrl);
            ctx.Log($"Ο λογαριασμός github.com/{login} δεν αναφέρει το {e.Data} στο προφίλ του· δεν εξετάζεται περαιτέρω.", "warn");
            return;
        }

        var owner = ctx.Emit(EventTypes.CodeRepoOwner, $"github.com/{login}", e, link: htmlUrl);
        if (owner is null) return;

        var repos = await ListReposAsync(login, ctx, ct);
        var repoEvents = new List<(GitHubRepo Repo, ScanEvent Event)>();
        foreach (var repo in repos.Take(MaxRepos))
            if (ctx.Emit(EventTypes.CodeRepo, repo.Html_Url, owner, link: repo.Html_Url) is { } ev)
                repoEvents.Add((repo, ev));

        if (ctx.Options.Gitleaks && repoEvents.Count > 0) await ScanWithGitleaksAsync(repoEvents, ctx, ct);
    }

    /// <summary>
    /// Ελέγχει αν ένα προφίλ GitHub ανήκει στο domain: το "blog" ή το "email" πρέπει να δείχνει σε αυτό.
    /// </summary>
    /// <param name="profile">Το JSON του προφίλ.</param>
    /// <param name="domain">Το domain-στόχος.</param>
    /// <returns><c>true</c> αν το προφίλ αναφέρει το domain.</returns>
    static bool BelongsToDomain(JsonElement profile, string domain)
    {
        var blog = profile.TryGetProperty("blog", out var b) ? b.GetString() : null;
        if (!string.IsNullOrWhiteSpace(blog))
        {
            var withScheme = blog.Contains("://") ? blog : "https://" + blog;
            if (Uri.TryCreate(withScheme, UriKind.Absolute, out var u) && Scope.NormalizeHost(u.Host) is { } host
                && Scope.InScope(host, domain))
                return true;
        }
        var email = profile.TryGetProperty("email", out var em) ? em.GetString() : null;
        return email is not null && email.EndsWith("@" + domain, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Ένα δημόσιο repository όπως το επιστρέφει το GitHub API.</summary>
    /// <param name="Name">Το όνομα.</param>
    /// <param name="Html_Url">Το URL του repo.</param>
    /// <param name="Fork">Αν είναι fork άλλου repo.</param>
    /// <param name="Size">Μέγεθος σε KB.</param>
    sealed record GitHubRepo(string Name, string Html_Url, bool Fork, long Size);

    /// <summary>
    /// Επιστρέφει τα δημόσια repos ενός λογαριασμού που δεν είναι forks, από το πιο πρόσφατα ενημερωμένο.
    /// </summary>
    /// <param name="login">Ο λογαριασμός.</param>
    /// <param name="ctx">Το context του scan.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Τα repos.</returns>
    async Task<List<GitHubRepo>> ListReposAsync(string login, ScanContext ctx, CancellationToken ct)
    {
        using var res = await http.CreateClient(HttpClients.GitHub).GetAsync($"users/{Uri.EscapeDataString(login)}/repos?per_page=100&type=owner&sort=pushed", ct);
        if (!EnsureOk(res, ctx)) return [];
        var repos = await res.Content.ReadFromJsonAsync<List<GitHubRepo>>(ct) ?? [];
        return repos.Where(r => !r.Fork).ToList();
    }

    /// <summary>
    /// Στέλνει τα repos ένα-ένα στο Gitleaks Scanner και εκπέμπει το αποτέλεσμα κάθε scan,
    /// με link προς τη σελίδα του scan εκεί.
    /// </summary>
    /// <param name="repos">Τα repos και τα events τους (για να μπουν τα αποτελέσματα κάτω από το σωστό repo στον γράφο).</param>
    /// <param name="ctx">Το context του scan.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Ένα task που ολοκληρώνεται όταν τελειώσουν όλα τα scans.</returns>
    async Task ScanWithGitleaksAsync(List<(GitHubRepo Repo, ScanEvent Event)> repos, ScanContext ctx, CancellationToken ct)
    {
        var health = await gitleaks.CheckHealthAsync(ct);
        if (!health.Available)
        {
            ctx.Log($"Το Gitleaks Scanner δεν απαντά στο {health.Url}. Ξεκίνησέ το (dotnet run --project src/GitleaksScanner.Api) και ξανατρέξε το scan.", "warn");
            return;
        }

        foreach (var (repo, ev) in repos.Take(MaxGitleaksScans))
        {
            var result = await gitleaks.ScanRepositoryAsync(repo.Html_Url, ct);
            if (!result.IsSuccess)
            {
                ctx.Log($"Gitleaks: {repo.Name}: {result.Error!.Message}", "warn");
                continue;
            }
            var r = result.Value!;
            ctx.Emit(EventTypes.LeakedSecrets, r.Total > 0 ? $"{repo.Name}: {r.Total} secrets" : $"{repo.Name}: καθαρό",
                ev, r.Total > 0 ? "high" : "info", r.Link);
        }
        if (repos.Count > MaxGitleaksScans)
            ctx.Log($"Σκαναρίστηκαν τα {MaxGitleaksScans} πιο πρόσφατα repos από τα {repos.Count}.");
    }

    /// <summary>
    /// Ελέγχει την απάντηση του GitHub. Αν έφτασε το όριο αιτημάτων ή απέτυχε, το καταγράφει στο log.
    /// </summary>
    /// <param name="res">Η απάντηση.</param>
    /// <param name="ctx">Το context του scan.</param>
    /// <returns><c>true</c> αν η απάντηση είναι επιτυχής.</returns>
    static bool EnsureOk(HttpResponseMessage res, ScanContext ctx)
    {
        if (res.IsSuccessStatusCode) return true;
        ctx.Log(res.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests
            ? "Το GitHub API έφτασε το όριο αιτημάτων. Συνδέσου με 'gh auth login' για μεγαλύτερο όριο."
            : $"Το GitHub API απάντησε {(int)res.StatusCode}.", "warn");
        return false;
    }
}
