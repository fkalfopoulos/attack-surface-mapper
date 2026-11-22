using AttackSurfaceMapper.Domain;

namespace AttackSurfaceMapper.Tests;

/// <summary>Tests για την αξιολόγηση παλιών URLs από το Wayback Machine.</summary>
public class HistoricUrlsTests
{
    /// <summary>Ελέγχει ότι τα ευαίσθητα αρχεία παίρνουν τον σωστό κίνδυνο.</summary>
    /// <param name="url">Το URL.</param>
    /// <param name="risk">Ο αναμενόμενος κίνδυνος.</param>
    [Theory]
    [InlineData("https://example.com/.env", "high")]
    [InlineData("https://example.com/.git/config", "high")]
    [InlineData("https://example.com/backup/db.sql.gz", "high")]
    [InlineData("https://example.com/site.zip", "medium")]
    [InlineData("https://example.com/backup-2024-03-01.tar.gz", "medium")]
    [InlineData("https://example.com/debug.log", "medium")]
    [InlineData("https://example.com/wp-admin/", "low")]
    [InlineData("https://api.example.com/swagger/index.html", "low")]
    public void Evaluate_RatesSensitiveFiles(string url, string risk) =>
        Assert.Equal(risk, HistoricUrls.Evaluate(url)?.Risk);

    /// <summary>Ελέγχει ότι οι συνηθισμένες σελίδες δεν θεωρούνται ενδιαφέρουσες.</summary>
    /// <param name="url">Το URL.</param>
    [Theory]
    [InlineData("https://example.com/")]
    [InlineData("https://example.com/about.html")]
    [InlineData("https://example.com/img/logo.png")]
    [InlineData("ftp://example.com/.env")]
    [InlineData("https://nmap.org/dist/nmap-7.95.tgz")]           // release, όχι backup
    [InlineData("https://example.com/6/data/sample-scan.log")]     // παράδειγμα, όχι log εφαρμογής
    [InlineData("http://example.com/a.htmlhttp://docs.example.org/api/login.html")]   // "κολλημένα" URLs του Wayback
    public void Evaluate_IgnoresOrdinaryUrls(string url) => Assert.Null(HistoricUrls.Evaluate(url));

    /// <summary>
    /// Ελέγχει ότι οι τιμές του query string κρύβονται πάντα (μπορεί να είναι tokens), και ότι
    /// ένα token στο URL αναφέρεται ως εύρημα.
    /// </summary>
    [Fact]
    public void Evaluate_MasksQueryValuesAndFlagsTokens()
    {
        var f = HistoricUrls.Evaluate("https://example.com/download?id=5&token=abc123SECRET");
        Assert.NotNull(f);
        Assert.Equal("medium", f.Risk);
        Assert.DoesNotContain("abc123SECRET", f.Url);
        Assert.Equal("https://example.com/download?id=•••&token=•••", f.Url);
    }
}
