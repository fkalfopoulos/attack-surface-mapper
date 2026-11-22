using AttackSurfaceMapper.Data;
using AttackSurfaceMapper.Engine;

namespace AttackSurfaceMapper.Tests;

/// <summary>Tests για τη σύγκριση δύο scans.</summary>
public class ScanDiffTests
{
    /// <summary>Φτιάχνει ένα event για τα tests.</summary>
    /// <param name="id">Το id.</param>
    /// <param name="type">Ο τύπος.</param>
    /// <param name="data">Η τιμή.</param>
    /// <param name="parent">Ο γονέας (<c>null</c> για τη ρίζα).</param>
    /// <returns>Το event.</returns>
    static ScanEvent Ev(long id, string type, string data, long? parent = 1) =>
        new(id, type, data, "test", parent, null, null, parent is null ? 0 : 1);

    static readonly ScanEvent[] Previous =
    [
        Ev(1, EventTypes.Domain, "example.com", parent: null),
        Ev(2, EventTypes.Host, "www.example.com"),
        Ev(3, EventTypes.Host, "old.example.com"),
    ];

    static readonly ScanEvent[] Current =
    [
        Ev(10, EventTypes.Domain, "example.com", parent: null),
        Ev(11, EventTypes.Host, "www.example.com"),
        Ev(12, EventTypes.Host, "new.example.com"),
    ];

    /// <summary>Ελέγχει ότι βρίσκονται σωστά τα νέα και τα εξαφανισμένα events.</summary>
    [Fact]
    public void Compare_FindsAddedAndRemoved()
    {
        var diff = ScanDiff.Compare(5, Previous, Current, running: false);

        Assert.Equal(5, diff.PreviousScanId);
        Assert.Equal([12L], diff.NewIds);
        Assert.NotNull(diff.Removed);
        Assert.Equal("old.example.com", Assert.Single(diff.Removed).Data);
    }

    /// <summary>Ελέγχει ότι ο ίδιος τύπος με την ίδια τιμή θεωρείται ίδιο event, ανεξάρτητα από το id.</summary>
    [Fact]
    public void Compare_MatchesByTypeAndData()
    {
        var diff = ScanDiff.Compare(5, Current, Current, running: false);
        Assert.Empty(diff.NewIds);
        Assert.Empty(diff.Removed!);
    }

    /// <summary>Ελέγχει ότι η ίδια τιμή με άλλο τύπο (π.χ. hostname αντί για affiliate) μετρά ως αλλαγή.</summary>
    [Fact]
    public void Compare_TreatsDifferentTypeAsDifferentEvent()
    {
        ScanEvent[] now = [Ev(20, EventTypes.Domain, "example.com", null), Ev(21, EventTypes.AffiliateHost, "www.example.com")];
        var diff = ScanDiff.Compare(5, Previous, now, running: false);
        Assert.Contains(21L, diff.NewIds);
    }

    /// <summary>
    /// Ελέγχει ότι όσο το scan τρέχει δεν αναφέρονται "εξαφανισμένα", γιατί θα ήταν όσα απλώς
    /// δεν έχουν βρεθεί ακόμα.
    /// </summary>
    [Fact]
    public void Compare_WhileRunning_DoesNotReportRemoved()
    {
        var diff = ScanDiff.Compare(5, Previous, Current, running: true);
        Assert.Null(diff.Removed);
        Assert.Equal([12L], diff.NewIds);
    }

    /// <summary>Ελέγχει ότι η ρίζα (το domain) δεν εμφανίζεται ποτέ ως "νέα".</summary>
    [Fact]
    public void Compare_NeverReportsRootAsNew()
    {
        ScanEvent[] now = [Ev(30, EventTypes.Domain, "other.com", null)];
        var diff = ScanDiff.Compare(5, Previous, now, running: false);
        Assert.Empty(diff.NewIds);
    }
}
