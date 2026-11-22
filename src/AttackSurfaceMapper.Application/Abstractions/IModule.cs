using AttackSurfaceMapper.Application.Engine;
using AttackSurfaceMapper.Domain;

namespace AttackSurfaceMapper.Application.Abstractions;

/// <summary>
/// Ένα module συλλογής πληροφοριών. Παρακολουθεί ορισμένους τύπους events και παράγει νέους.
/// </summary>
public interface IModule
{
    /// <summary>Το μοναδικό όνομα του module (π.χ. "dns_resolve").</summary>
    string Name { get; }

    /// <summary>Σύντομη ελληνική περιγραφή του τι κάνει το module.</summary>
    string Description { get; }

    /// <summary>Πόσο αγγίζει τον στόχο. Τα modules πάνω από το επίπεδο του scan δεν τρέχουν.</summary>
    Footprint Level { get; }

    /// <summary>Οι τύποι events που θέλει να λαμβάνει το module.</summary>
    IReadOnlyCollection<string> Watched { get; }

    /// <summary>Οι τύποι events που μπορεί να παράγει (για το UI και την τεκμηρίωση).</summary>
    IReadOnlyCollection<string> Produced { get; }

    /// <summary>
    /// Επεξεργάζεται ένα event και παράγει νέα events μέσω του <paramref name="ctx"/>.
    /// </summary>
    /// <param name="e">Το event που πρέπει να επεξεργαστεί.</param>
    /// <param name="ctx">Το context του scan, για εκπομπή νέων events, logging και HTTP clients.</param>
    /// <param name="ct">Ακυρώνεται όταν σταματήσει το scan.</param>
    /// <returns>Ένα task που ολοκληρώνεται όταν τελειώσει η επεξεργασία.</returns>
    Task HandleAsync(ScanEvent e, ScanContext ctx, CancellationToken ct);

    /// <summary>
    /// Σε πόσους στόχους (events) το πολύ τρέχει ένα footprint module ανά scan, για να μην
    /// κατακλύσει τον στόχο με αιτήματα. Τα passive modules δεν έχουν όριο.
    /// </summary>
    int MaxTargets => 150;
}
