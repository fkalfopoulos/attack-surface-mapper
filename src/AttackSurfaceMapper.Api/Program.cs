using AttackSurfaceMapper.Api;
using AttackSurfaceMapper.Application;
using AttackSurfaceMapper.Infrastructure;
using Serilog;
using Serilog.Events;

var builder = WebApplication.CreateBuilder(args);

// Η βάση και τα logs μένουν στο appdata/ (ΟΧΙ "data/": σε macOS θα μπερδευόταν με φάκελο "Data").
var dataDir = Path.Combine(builder.Environment.ContentRootPath, "appdata");

// ---------- Logging (Serilog) ----------
// Κονσόλα και αρχείο ανά ημέρα (κρατιούνται 14). Ο υπόλοιπος κώδικας γράφει μέσω ILogger<T>.
// Τα modules γράφουν επιπλέον στο log κάθε scan (καρτέλα "Log" στο UI).
builder.Host.UseSerilog((ctx, cfg) => cfg
    .ReadFrom.Configuration(ctx.Configuration)
    .MinimumLevel.Information()
    .MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning)
    .MinimumLevel.Override("System.Net.Http.HttpClient", LogEventLevel.Warning)
    .Enrich.FromLogContext()
    .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}")
    .WriteTo.File(Path.Combine(dataDir, "logs", "attack-surface-mapper-.log"),
        rollingInterval: RollingInterval.Day, retainedFileCountLimit: 14,
        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}"));

// ---------- Ασφάλεια ----------
// Μόνο localhost, και μόνο Host "localhost": αλλιώς μια κακόβουλη ιστοσελίδα θα μπορούσε,
// με DNS rebinding, να ξεκινά scans μέσω του browser σου.
builder.WebHost.UseUrls("http://localhost:5090");
builder.Configuration["AllowedHosts"] = "localhost";

// ---------- Layers ----------
builder.Services.AddApplication();
builder.Services.AddInfrastructure(new InfrastructureOptions(
    dataDir,
    new Uri(builder.Configuration["GitleaksScanner:Url"] ?? "http://localhost:5080/")));
builder.Services.AddProblemDetails();

var app = builder.Build();

app.UseExceptionHandler();
app.UseSerilogRequestLogging(o =>
{
    o.MessageTemplate = "HTTP {RequestMethod} {RequestPath} → {StatusCode} σε {Elapsed:0} ms";
    // Το UI ρωτά κάθε 2-3 δευτερόλεπτα όσο τρέχει ένα scan: αυτά τα αιτήματα μόνο σε Debug.
    o.GetLevel = (ctx, _, ex) => ex is not null || ctx.Response.StatusCode >= 500 ? LogEventLevel.Error
        : ctx.Request.Method == "GET" ? LogEventLevel.Debug : LogEventLevel.Information;
});
app.UseDefaultFiles();
app.UseStaticFiles();
app.MapEndpoints();

try
{
    Log.Information("Το Attack Surface Mapper ξεκινά στο http://localhost:5090 (GitHub API {GitHub})",
        AttackSurfaceMapper.Infrastructure.DependencyInjection.HasGitHubToken() ? "με token" : "χωρίς token, 60 αιτήματα/ώρα");
    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Το Attack Surface Mapper σταμάτησε απρόσμενα");
    throw;
}
finally
{
    Log.CloseAndFlush();
}
