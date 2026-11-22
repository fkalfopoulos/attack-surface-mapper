using System.Net;
using AttackSurfaceMapper.Engine;

namespace AttackSurfaceMapper.Tests;

/// <summary>Tests για την προστασία SSRF: σε ποιες διευθύνσεις επιτρέπεται σύνδεση.</summary>
public class NetGuardTests
{
    /// <summary>
    /// Ελέγχει ότι μπλοκάρονται όλες οι μη δημόσιες διευθύνσεις, ειδικά το cloud metadata
    /// (169.254.169.254) και οι IPv6 μορφές τους.
    /// </summary>
    /// <param name="ip">Η διεύθυνση.</param>
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("10.1.2.3")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.255")]
    [InlineData("192.168.1.1")]
    [InlineData("169.254.169.254")]   // cloud metadata
    [InlineData("100.64.0.1")]        // CGNAT
    [InlineData("0.0.0.0")]
    [InlineData("224.0.0.1")]         // multicast
    [InlineData("::1")]
    [InlineData("fe80::1")]           // link-local
    [InlineData("fd00::1")]           // unique local
    [InlineData("::ffff:127.0.0.1")]  // IPv4-mapped loopback
    [InlineData("::ffff:10.0.0.1")]
    public void IsPublic_BlocksNonPublicAddresses(string ip) => Assert.False(NetGuard.IsPublic(IPAddress.Parse(ip)));

    /// <summary>Ελέγχει ότι οι δημόσιες διευθύνσεις επιτρέπονται.</summary>
    /// <param name="ip">Η διεύθυνση.</param>
    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    [InlineData("172.32.0.1")]        // ακριβώς έξω από το 172.16.0.0/12
    [InlineData("2606:4700:4700::1111")]
    public void IsPublic_AllowsPublicAddresses(string ip) => Assert.True(NetGuard.IsPublic(IPAddress.Parse(ip)));
}
