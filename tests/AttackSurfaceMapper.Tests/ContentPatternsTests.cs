using AttackSurfaceMapper.Domain;

namespace AttackSurfaceMapper.Tests;

/// <summary>Tests για την αναγνώριση secrets, emails και buckets σε HTML/JavaScript.</summary>
public class ContentPatternsTests
{
    // Ψεύτικα secrets με τη μορφή των πραγματικών, μόνο για τα tests. Φτιάχνονται ενώνοντας
    // κομμάτια, ώστε ο κώδικας να μην περιέχει πουθενά ολόκληρο "secret": αλλιώς το gitleaks και
    // το GitHub Push Protection θα τα έβρισκαν (σωστά, γιατί δεν μπορούν να ξέρουν ότι είναι ψεύτικα).
    static readonly string AwsKey = "AKIA" + "IOSFODNN7EXAMPLQ";
    static readonly string GitHubToken = "ghp" + "_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5";
    static readonly string StripeKey = "sk" + "_live_" + "51HxQ2bL8kN4mT7vR9wY3zA6cD1eF5gH";
    static readonly string StripePublishable = "pk" + "_live_" + "51HxQ2bL8kN4mT7vR9wY3zA6cD1eF5gH";

    /// <summary>Ελέγχει ότι βρίσκονται τα secrets μέσα σε JavaScript, με σωστό είδος.</summary>
    [Fact]
    public void FindSecrets_DetectsKnownFormats()
    {
        var js = $"const cfg={{aws:\"{AwsKey}\",gh:'{GitHubToken}'}};fetch(x,{{key:\"{StripeKey}\"}})";
        var kinds = ContentPatterns.FindSecrets(js).Select(s => s.Kind).ToList();
        Assert.Contains("AWS Access Key", kinds);
        Assert.Contains("GitHub token", kinds);
        Assert.Contains("Stripe secret key", kinds);
    }

    /// <summary>
    /// Ελέγχει το πιο σημαντικό: η πλήρης τιμή ενός secret δεν εμφανίζεται ΠΟΤΕ στο αποτέλεσμα,
    /// οπότε δεν μπορεί να καταλήξει στη βάση, στο UI ή στα logs.
    /// </summary>
    [Fact]
    public void FindSecrets_NeverReturnsTheFullSecret()
    {
        var found = ContentPatterns.FindSecrets($"x = '{GitHubToken}'");
        var s = Assert.Single(found);
        Assert.DoesNotContain(GitHubToken, s.Masked);
        Assert.Equal("••••••vW3xY5", s.Masked);
    }

    /// <summary>Ελέγχει ότι το Stripe publishable key (που είναι δημόσιο από τη φύση του) δεν αναφέρεται.</summary>
    [Fact]
    public void FindSecrets_IgnoresPublishableKeys() =>
        Assert.Empty(ContentPatterns.FindSecrets($"Stripe('{StripePublishable}')"));

    /// <summary>Ελέγχει ότι το ίδιο secret δύο φορές μετρά ως ένα.</summary>
    [Fact]
    public void FindSecrets_DeduplicatesValues() =>
        Assert.Single(ContentPatterns.FindSecrets($"{AwsKey} {AwsKey}"));

    /// <summary>Ελέγχει ότι αγνοούνται ονόματα εικόνων που μοιάζουν με email (π.χ. logo@2x.png).</summary>
    [Fact]
    public void FindEmails_IgnoresRetinaImageNames()
    {
        var emails = ContentPatterns.FindEmails("<img src='logo@2x.png'> Contact: Info@Example.com");
        Assert.Equal(["info@example.com"], emails);
    }

    /// <summary>Ελέγχει ότι αναγνωρίζονται buckets σε S3, Azure και Google Cloud.</summary>
    [Fact]
    public void FindBuckets_DetectsMajorClouds()
    {
        var text = "https://acme-assets.s3.amazonaws.com/a.js https://acmestore.blob.core.windows.net/x " +
                   "https://storage.googleapis.com/acme-public/file";
        var buckets = ContentPatterns.FindBuckets(text);
        Assert.Contains("acme-assets.s3.amazonaws.com", buckets);
        Assert.Contains("acmestore.blob.core.windows.net", buckets);
        Assert.Contains("storage.googleapis.com/acme-public", buckets);
    }
}
