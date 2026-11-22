using AttackSurfaceMapper.Engine;

namespace AttackSurfaceMapper.Tests;

/// <summary>Tests για την κανονικοποίηση hostnames και τον έλεγχο scope.</summary>
public class ScopeTests
{
    /// <summary>Ελέγχει ότι τα hostnames γίνονται πεζά, χωρίς τελεία στο τέλος και χωρίς wildcard.</summary>
    /// <param name="raw">Το hostname όπως ήρθε από την πηγή.</param>
    /// <param name="expected">Η αναμενόμενη κανονικοποιημένη μορφή.</param>
    [Theory]
    [InlineData("API.Example.COM", "api.example.com")]
    [InlineData("www.example.com.", "www.example.com")]
    [InlineData("*.example.com", "example.com")]
    [InlineData("  mail.example.com  ", "mail.example.com")]
    public void NormalizeHost_CanonicalizesNames(string raw, string expected) =>
        Assert.Equal(expected, Scope.NormalizeHost(raw));

    /// <summary>Ελέγχει ότι τα ελληνικά (IDN) domains μετατρέπονται σε punycode.</summary>
    [Fact]
    public void NormalizeHost_ConvertsIdnToPunycode() =>
        Assert.StartsWith("xn--", Scope.NormalizeHost("παράδειγμα.gr"));

    /// <summary>Ελέγχει ότι άκυρα hostnames απορρίπτονται.</summary>
    /// <param name="raw">Άκυρο hostname.</param>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("localhost")]                 // χωρίς τελεία
    [InlineData("-bad.example.com")]          // label που ξεκινά με παύλα
    [InlineData("exa mple.com")]
    [InlineData("example.com/path")]
    public void NormalizeHost_RejectsInvalid(string? raw) => Assert.Null(Scope.NormalizeHost(raw));

    /// <summary>Ελέγχει ότι το ίδιο το domain και τα subdomains του είναι μέσα στο scope.</summary>
    /// <param name="host">Το hostname.</param>
    [Theory]
    [InlineData("example.com")]
    [InlineData("api.example.com")]
    [InlineData("a.b.c.example.com")]
    public void InScope_AcceptsTargetAndSubdomains(string host) => Assert.True(Scope.InScope(host, "example.com"));

    /// <summary>
    /// Ελέγχει ότι domains που απλώς <i>τελειώνουν</i> με το ίδιο κείμενο δεν θεωρούνται in scope
    /// (το notexample.com δεν είναι subdomain του example.com).
    /// </summary>
    /// <param name="host">Το hostname.</param>
    [Theory]
    [InlineData("notexample.com")]
    [InlineData("example.com.evil.net")]
    [InlineData("cdn.cloudflare.com")]
    public void InScope_RejectsOtherDomains(string host) => Assert.False(Scope.InScope(host, "example.com"));

    /// <summary>Ελέγχει ότι βρίσκεται σωστά το όνομα του οργανισμού, και με δεύτερου επιπέδου TLDs.</summary>
    /// <param name="domain">Το domain.</param>
    /// <param name="expected">Το αναμενόμενο όνομα.</param>
    [Theory]
    [InlineData("example.com", "example")]
    [InlineData("www.example.com", "example")]
    [InlineData("example.co.uk", "example")]
    [InlineData("shop.example.com.gr", "example")]
    public void OrgLabel_ExtractsOrganizationName(string domain, string expected) =>
        Assert.Equal(expected, Scope.OrgLabel(domain));
}
