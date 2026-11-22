namespace AttackSurfaceMapper.Infrastructure.Network;

/// <summary>Τα ονόματα των HTTP clients που ρυθμίζονται στο <see cref="DependencyInjection"/>.</summary>
public static class HttpClients
{
    /// <summary>Για APIs τρίτων (crt.sh, RDAP, RIPEstat, Wayback, blocklists). Δεν αγγίζει τον στόχο.</summary>
    public const string External = "external";
    /// <summary>Για τον ίδιο τον στόχο: μόνο δημόσιες IP μέσω <see cref="NetGuard"/>, χωρίς αυτόματα redirects.</summary>
    public const string Target = "target";
    /// <summary>Για το GitHub API (με token, αν υπάρχει).</summary>
    public const string GitHub = "github";
    /// <summary>Για το Gitleaks Scanner.</summary>
    public const string Gitleaks = "gitleaks";
}
