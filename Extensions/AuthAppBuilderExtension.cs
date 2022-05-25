namespace Microsoft.Extensions.DependencyInjection;

public static class AuthAppBuilderExtension
{
    public static IApplicationBuilder UseJwtAuthentication(this IApplicationBuilder app)
    {
        if (app == null) throw new ArgumentNullException(nameof(app));

        return app.UseMiddleware<JwtAuthenticationHeaderMiddleware>();
    }
}