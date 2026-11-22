using System.Net;
using System.Text.Json;
using AttackSurfaceMapper.Application.Abstractions;
using AttackSurfaceMapper.Application.Engine;
using AttackSurfaceMapper.Domain;
using AttackSurfaceMapper.Infrastructure.Network;

namespace AttackSurfaceMapper.Infrastructure.Modules;

/// <summary>
/// Διαβάζει τα στοιχεία καταχώρισης του domain μέσω RDAP: registrar, ημερομηνίες, emails επικοινωνίας.
/// </summary>
/// <remarks>
/// Το RDAP είναι ο σύγχρονος διάδοχος του WHOIS: επιστρέφει δομημένο JSON αντί για ελεύθερο κείμενο.
/// Το rdap.org κάνει redirect στον σωστό registry για κάθε TLD.
/// </remarks>
/// <param name="http">Το factory των HTTP clients.</param>
public sealed class RdapModule(IHttpClientFactory http) : IModule
{
    /// <inheritdoc/>
    public string Name => "rdap";
    /// <inheritdoc/>
    public string Description => "Registrar, ημερομηνίες καταχώρισης/λήξης και emails του domain (RDAP / WHOIS).";
    /// <inheritdoc/>
    public Footprint Level => Footprint.Passive;
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Watched { get; } = [EventTypes.Domain];
    /// <inheritdoc/>
    public IReadOnlyCollection<string> Produced { get; } =
        [EventTypes.Registrar, EventTypes.DomainDates, EventTypes.Email, EventTypes.Host, EventTypes.AffiliateHost];

    /// <summary>
    /// Ζητά τα στοιχεία RDAP του domain και εκπέμπει registrar, ημερομηνίες, nameservers και emails.
    /// Σημειώνει κίνδυνο αν το domain λήγει σε λιγότερο από 30 ημέρες.
    /// </summary>
    /// <param name="e">Το domain-στόχος.</param>
    /// <param name="ctx">Το context του scan.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Ένα task που ολοκληρώνεται όταν διαβαστούν τα στοιχεία.</returns>
    public async Task HandleAsync(ScanEvent e, ScanContext ctx, CancellationToken ct)
    {
        using var res = await http.CreateClient(HttpClients.External).GetAsync($"https://rdap.org/domain/{Uri.EscapeDataString(e.Data)}", ct);
        if (res.StatusCode == HttpStatusCode.NotFound)
        {
            ctx.Log($"Δεν υπάρχουν στοιχεία RDAP για το {e.Data} (το TLD μπορεί να μην υποστηρίζει RDAP).", "warn");
            return;
        }
        res.EnsureSuccessStatusCode();
        using var doc = await JsonDocument.ParseAsync(await res.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
        var root = doc.RootElement;

        EmitDates(e, root, ctx);

        if (root.TryGetProperty("nameservers", out var nss))
            foreach (var ns in nss.EnumerateArray())
                if (ns.TryGetProperty("ldhName", out var n)) ctx.Emit(EventTypes.Host, n.GetString(), e);

        if (root.TryGetProperty("entities", out var entities)) WalkEntities(e, entities, ctx, depth: 0);
    }

    /// <summary>
    /// Εκπέμπει τις ημερομηνίες καταχώρισης και λήξης. Domain που λήγει σε λιγότερο από 30 ημέρες
    /// σημειώνεται ως κίνδυνος, γιατί αν δεν ανανεωθεί μπορεί να το αγοράσει κάποιος άλλος.
    /// </summary>
    /// <param name="e">Το domain.</param>
    /// <param name="root">Η ρίζα του RDAP JSON.</param>
    /// <param name="ctx">Το context του scan.</param>
    static void EmitDates(ScanEvent e, JsonElement root, ScanContext ctx)
    {
        if (!root.TryGetProperty("events", out var events)) return;
        DateTimeOffset? registered = null, expires = null;
        foreach (var ev in events.EnumerateArray())
        {
            var action = ev.TryGetProperty("eventAction", out var a) ? a.GetString() : null;
            if (!ev.TryGetProperty("eventDate", out var d) || !DateTimeOffset.TryParse(d.GetString(), out var date)) continue;
            if (action == "registration") registered = date;
            if (action == "expiration") expires = date;
        }
        if (registered is null && expires is null) return;

        var text = $"Καταχώριση: {registered:yyyy-MM-dd} · Λήξη: {expires:yyyy-MM-dd}";
        string? risk = null;
        if (expires is { } x && x - DateTimeOffset.UtcNow < TimeSpan.FromDays(30))
        {
            risk = x < DateTimeOffset.UtcNow ? "high" : "medium";
            text += x < DateTimeOffset.UtcNow ? " (ΕΧΕΙ ΛΗΞΕΙ)" : $" (λήγει σε {(x - DateTimeOffset.UtcNow).Days} ημέρες)";
        }
        ctx.Emit(EventTypes.DomainDates, text, e, risk);
    }

    /// <summary>
    /// Διατρέχει τις οντότητες του RDAP (registrar, registrant, abuse contact…) και εκπέμπει
    /// το όνομα του registrar και όσα emails δεν είναι κρυμμένα για λόγους privacy.
    /// </summary>
    /// <param name="e">Το domain.</param>
    /// <param name="entities">Ο πίνακας <c>entities</c> του RDAP.</param>
    /// <param name="ctx">Το context του scan.</param>
    /// <param name="depth">Βάθος αναδρομής (οι οντότητες μπορεί να περιέχουν άλλες οντότητες).</param>
    static void WalkEntities(ScanEvent e, JsonElement entities, ScanContext ctx, int depth)
    {
        if (depth > 3) return;
        foreach (var entity in entities.EnumerateArray())
        {
            var roles = entity.TryGetProperty("roles", out var r)
                ? r.EnumerateArray().Select(x => x.GetString()).ToHashSet()
                : [];
            var (fn, emails) = ReadVCard(entity);

            if (roles.Contains("registrar") && fn is not null) ctx.Emit(EventTypes.Registrar, fn, e);
            foreach (var email in emails.Where(IsRealEmail)) ctx.Emit(EventTypes.Email, email, e);

            if (entity.TryGetProperty("entities", out var nested)) WalkEntities(e, nested, ctx, depth + 1);
        }
    }

    /// <summary>
    /// Διαβάζει το όνομα (<c>fn</c>) και τα emails από το vCard μιας οντότητας RDAP.
    /// </summary>
    /// <param name="entity">Η οντότητα.</param>
    /// <returns>Το όνομα (ή <c>null</c>) και τα emails.</returns>
    /// <example>Μορφή: <c>["vcard", [["fn", {}, "text", "Name"], ["email", {}, "text", "a@b.c"]]]</c></example>
    static (string? Fn, List<string> Emails) ReadVCard(JsonElement entity)
    {
        string? fn = null;
        var emails = new List<string>();
        if (!entity.TryGetProperty("vcardArray", out var vcard) || vcard.GetArrayLength() < 2) return (fn, emails);
        foreach (var prop in vcard[1].EnumerateArray())
        {
            if (prop.GetArrayLength() < 4 || prop[3].ValueKind != JsonValueKind.String) continue;
            var name = prop[0].GetString();
            if (name == "fn") fn = prop[3].GetString();
            if (name == "email") emails.Add(prop[3].GetString()!);
        }
        return (fn, emails);
    }

    /// <summary>
    /// Ελέγχει αν ένα email είναι πραγματικό και όχι placeholder privacy (π.χ. "REDACTED FOR PRIVACY").
    /// </summary>
    /// <param name="email">Το email.</param>
    /// <returns><c>true</c> αν μοιάζει με πραγματική διεύθυνση.</returns>
    static bool IsRealEmail(string email) =>
        email.Contains('@') && !email.Contains("redacted", StringComparison.OrdinalIgnoreCase)
        && !email.Contains("privacy", StringComparison.OrdinalIgnoreCase);
}
