using AttackSurfaceMapper.Application.Services;

namespace AttackSurfaceMapper.Tests;

/// <summary>Tests για τον έλεγχο του στόχου που δίνει ο χρήστης.</summary>
public class ApiTests
{
    /// <summary>Ελέγχει ότι από URL κρατιέται μόνο το domain, χωρίς scheme, path και "www.".</summary>
    /// <param name="raw">Αυτό που έγραψε ο χρήστης.</param>
    /// <param name="expected">Το αναμενόμενο domain.</param>
    [Theory]
    [InlineData("example.com", "example.com")]
    [InlineData("https://www.example.com/page?x=1", "example.com")]
    [InlineData("WWW.Example.com", "example.com")]
    [InlineData("example.com/path", "example.com")]
    [InlineData("api.example.com", "api.example.com")]
    [InlineData("www.example.co.uk", "example.co.uk")]
    [InlineData("www.co.uk", "www.co.uk")]   // δεν αφαιρείται το "www." αν μένει μόνο η κατάληξη
    public void ParseTarget_ExtractsDomain(string raw, string expected) =>
        Assert.Equal(expected, ScanAppService.ParseTarget(raw));

    /// <summary>Ελέγχει ότι απορρίπτονται IP διευθύνσεις και άκυρα domains.</summary>
    /// <param name="raw">Άκυρος στόχος.</param>
    [Theory]
    [InlineData(null)]
    [InlineData("   ")]
    [InlineData("8.8.8.8")]
    [InlineData("::1")]
    [InlineData("localhost")]
    [InlineData("not a domain")]
    public void ParseTarget_RejectsInvalid(string? raw) => Assert.Null(ScanAppService.ParseTarget(raw));
}
