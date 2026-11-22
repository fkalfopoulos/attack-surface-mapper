using System.Diagnostics;

namespace AttackSurfaceMapper.Infrastructure.Network;

/// <summary>
/// Βρίσκει GitHub token για το GitHub API, ώστε το όριο να είναι 5000 αιτήματα την ώρα αντί για 60.
/// </summary>
public static class GitHubToken
{
    /// <summary>
    /// Επιστρέφει το token από τη μεταβλητή περιβάλλοντος <c>GITHUB_TOKEN</c> ή, αν δεν υπάρχει,
    /// από το GitHub CLI (<c>gh auth token</c>).
    /// </summary>
    /// <returns>Το token, ή <c>null</c> αν δεν βρέθηκε κανένα.</returns>
    /// <remarks>Το token χρησιμοποιείται μόνο για κλήσεις στο api.github.com και δεν αποθηκεύεται πουθενά.</remarks>
    public static string? Resolve()
    {
        var env = Environment.GetEnvironmentVariable("GITHUB_TOKEN");
        if (!string.IsNullOrWhiteSpace(env)) return env.Trim();

        try
        {
            using var proc = Process.Start(new ProcessStartInfo("gh", ["auth", "token"])
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            });
            if (proc is null) return null;
            var output = proc.StandardOutput.ReadToEnd().Trim();
            if (!proc.WaitForExit(5000)) { proc.Kill(); return null; }
            return proc.ExitCode == 0 && output.Length > 0 ? output : null;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return null;   // το gh δεν είναι εγκατεστημένο
        }
    }
}
