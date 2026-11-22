using System.Net;
using System.Reflection;
using AttackSurfaceMapper.Application.Abstractions;
using AttackSurfaceMapper.Application.Engine;
using AttackSurfaceMapper.Domain;
using DnsClient;

namespace AttackSurfaceMapper.Infrastructure.Modules.Active;

/// <summary>
/// ACTIVE: δοκιμάζει ~300 συνηθισμένα ονόματα subdomains (vpn, jenkins, staging…) για να βρει
/// όσα δεν εμφανίζονται σε καμία δημόσια πηγή.
/// </summary>
/// <remarks>
/// Πολλά domains έχουν <b>wildcard DNS</b> (κάθε όνομα απαντά με την ίδια IP). Τότε κάθε λέξη θα
/// φαινόταν "υπαρκτή". Γι' αυτό πρώτα ρωτάμε δύο τυχαία ονόματα: αν απαντήσουν, όσα subdomains
/// δείχνουν στις ίδιες IP αγνοούνται.
/// </remarks>
/// <param name="dns">Ο DNS client.</param>
public sealed class DnsBruteforceModule(ILookupClient dns) : IModule
{
    /// <summary>Πόσα DNS ερωτήματα ταυτόχρονα.</summary>
    const int Concurrency = 15;

    /// <summary>Η λίστα λέξεων, από το ενσωματωμένο αρχείο <c>subdomains.txt</c>.</summary>
    static readonly Lazy<string[]> Words = new(LoadWords);

    /// <inheritdoc/>
    public string Name => "dns_bruteforce";
    /// <inheritdoc/>
    public string Description => $"Δοκιμή ~{Words.Value.Length} συνηθισμένων ονομάτων subdomains, με ανίχνευση wildcard DNS.";
    /// <inheritdoc/>
    public Footprint Level => Footprint.Active;
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Watched { get; } = [EventTypes.Domain];
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Produced { get; } = [EventTypes.Host];

    /// <summary>
    /// Ελέγχει για wildcard DNS και μετά δοκιμάζει κάθε λέξη ως subdomain, εκπέμποντας όσα υπάρχουν.
    /// </summary>
    /// <param name="e">Το domain-στόχος.</param>
    /// <param name="ctx">Το context του scan.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Ένα task που ολοκληρώνεται όταν δοκιμαστούν όλες οι λέξεις.</returns>
    public async Task HandleAsync(ScanEvent e, ScanContext ctx, CancellationToken ct)
    {
        var wildcard = new HashSet<IPAddress>();
        foreach (var _ in Enumerable.Range(0, 2))
            wildcard.UnionWith(await ResolveAsync($"wc-{Guid.NewGuid():N}.{e.Data}", ct));
        if (wildcard.Count > 0)
            ctx.Log($"Wildcard DNS: κάθε όνομα απαντά με {string.Join(", ", wildcard)}· αυτές οι απαντήσεις αγνοούνται.", "warn");

        var found = 0;
        using var slots = new SemaphoreSlim(Concurrency);
        await Task.WhenAll(Words.Value.Select(async word =>
        {
            await slots.WaitAsync(ct);
            try
            {
                var host = $"{word}.{e.Data}";
                var ips = await ResolveAsync(host, ct);
                if (ips.Count > 0 && !ips.IsSubsetOf(wildcard))
                {
                    ctx.Emit(EventTypes.Host, host, e);
                    Interlocked.Increment(ref found);
                }
            }
            finally { slots.Release(); }
        }));
        ctx.Log($"DNS brute force: {found} από {Words.Value.Length} ονόματα υπάρχουν.");
    }

    /// <summary>Βρίσκει τις IPv4/IPv6 ενός ονόματος.</summary>
    /// <param name="name">Το όνομα.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Οι IP (κενό σύνολο αν δεν υπάρχει).</returns>
    async Task<HashSet<IPAddress>> ResolveAsync(string name, CancellationToken ct)
    {
        var a = await dns.QueryAsync(name, QueryType.A, cancellationToken: ct);
        var ips = a.Answers.ARecords().Select(r => r.Address).ToHashSet();
        if (ips.Count == 0)
        {
            var aaaa = await dns.QueryAsync(name, QueryType.AAAA, cancellationToken: ct);
            ips.UnionWith(aaaa.Answers.AaaaRecords().Select(r => r.Address));
        }
        return ips;
    }

    /// <summary>Διαβάζει τη λίστα λέξεων από το ενσωματωμένο αρχείο του assembly.</summary>
    /// <returns>Οι λέξεις, χωρίς κενές γραμμές και διπλότυπα.</returns>
    static string[] LoadWords()
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("subdomains.txt")
            ?? throw new InvalidOperationException("Λείπει το ενσωματωμένο subdomains.txt.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(w => w.ToLowerInvariant()).Distinct().ToArray();
    }
}
