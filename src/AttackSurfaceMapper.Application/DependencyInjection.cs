using AttackSurfaceMapper.Application.Engine;
using AttackSurfaceMapper.Application.Services;
using Microsoft.Extensions.DependencyInjection;

namespace AttackSurfaceMapper.Application;

/// <summary>Καταχώριση των υπηρεσιών του Application layer στο dependency injection.</summary>
public static class DependencyInjection
{
    /// <summary>Καταχωρεί τη μηχανή των scans και τις use cases.</summary>
    /// <param name="services">Η συλλογή υπηρεσιών.</param>
    /// <returns>Την ίδια συλλογή, για αλυσιδωτές κλήσεις.</returns>
    public static IServiceCollection AddApplication(this IServiceCollection services)
    {
        services.AddSingleton<ScanManager>();
        services.AddSingleton<ScanAppService>();
        return services;
    }
}
