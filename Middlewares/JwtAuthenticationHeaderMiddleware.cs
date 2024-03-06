using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using Netcorext.Auth;

namespace Microsoft.Extensions.DependencyInjection;

public class JwtAuthenticationHeaderMiddleware
{
    private readonly RequestDelegate _next;

    public JwtAuthenticationHeaderMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var headerValue = context.Request.Headers["Authorization"];

        if (!AuthenticationHeaderValue.TryParse(headerValue, out var authHeader) || string.IsNullOrWhiteSpace(authHeader.Parameter))
        {
            await _next(context);

            return;
        }

        var (isValid, claimsPrincipal) = authHeader.Scheme.ToUpper() switch
                                         {
                                             Constants.OAuth.TOKEN_TYPE_BASIC_NORMALIZED => GetBasicClaimsIdentity(authHeader.Parameter),
                                             Constants.OAuth.TOKEN_TYPE_BEARER_NORMALIZED => GetBearerClaimsIdentity(authHeader.Parameter),
                                             _ => (false, null)
                                         };

        if (isValid) context.User = claimsPrincipal!;

        await _next(context);
    }

    private (bool IsValid, ClaimsPrincipal? ClaimsPrincipal) GetBasicClaimsIdentity(string token)
    {
        var raw = Encoding.UTF8.GetString(Convert.FromBase64String(token));

        var client = raw.Split(":", StringSplitOptions.RemoveEmptyEntries);

        if (client.Length != 2 || !long.TryParse(client[0], out var clientId)) return (false, null);

        var claims = new List<Claim>
                     {
                         new(ClaimTypes.Name, client[0]),
                         new(ClaimTypes.UserData, token)
                     };

        var claimsIdentity = new ClaimsIdentity(claims.ToArray(), "AuthenticationTypes.Basic", ClaimTypes.Name, ClaimTypes.Role);

        return (true, new ClaimsPrincipal(claimsIdentity));
    }

    private (bool IsValid, ClaimsPrincipal? ClaimsPrincipal) GetBearerClaimsIdentity(string token)
    {
        var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();

        if (!jwtSecurityTokenHandler.CanReadToken(token)) return (false, null);

        var jwt = jwtSecurityTokenHandler.ReadJwtToken(token);

        var claims = new List<Claim>
                     {
                         new(ClaimTypes.UserData, token)
                     };

        foreach (var tokenClaim in jwt.Claims)
        {
            switch (tokenClaim.Type)
            {
                case JwtRegisteredClaimNames.NameId:
                case JwtRegisteredClaimNames.UniqueName:
                    claims.Add(new Claim(ClaimTypes.Name, tokenClaim.Value, tokenClaim.ValueType, tokenClaim.Issuer, tokenClaim.OriginalIssuer));

                    break;
                case "role":
                case "roles":
                    claims.Add(new Claim(ClaimTypes.Role, tokenClaim.Value, tokenClaim.ValueType, tokenClaim.Issuer, tokenClaim.OriginalIssuer));

                    break;
                default:
                    claims.Add(tokenClaim);

                    break;
            }
        }

        var claimsIdentity = new ClaimsIdentity(claims.ToArray(), "AuthenticationTypes.Federation", ClaimTypes.Name, ClaimTypes.Role);

        return (true, new ClaimsPrincipal(claimsIdentity));
    }
}
