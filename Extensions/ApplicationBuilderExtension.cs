using System.Reflection;
using System.Text.RegularExpressions;
using Google.Protobuf.WellKnownTypes;
using Grpc.AspNetCore.Server;
using Grpc.Net.Client;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Options;
using Netcorext.Auth;
using Netcorext.Auth.Attributes;
using Netcorext.Auth.Enums;
using Netcorext.Auth.Extensions;
using Netcorext.Auth.Extensions.AspNetCore.Settings;
using Netcorext.Auth.Protobufs;

namespace Microsoft.Extensions.DependencyInjection;

public static class ApplicationBuilderExtension
{
    private static readonly Regex RegexRoutePattern = new(@"\{([^:]+):apiVersion\}", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static IApplicationBuilder RegisterPermissionEndpoints(this IApplicationBuilder builder, Action<IServiceProvider, RegisterConfig>? configure, Func<IServiceProvider, PermissionEndpoint, bool>? handler = null, params PermissionEndpoint[]? otherPermissionEndpoints)
    {
        var app = (WebApplication)builder;

        var config = new RegisterConfig();

        using var scope = app.Services.CreateScope();

        var logger = scope.ServiceProvider.GetRequiredService<ILogger<RouteService.RouteServiceClient>>();

        configure?.Invoke(scope.ServiceProvider, config);

        if (string.IsNullOrWhiteSpace(config.RouteServiceUrl))
            throw new ArgumentNullException(nameof(config.RouteServiceUrl));

        if (string.IsNullOrWhiteSpace(config.HttpBaseUrl))
            throw new ArgumentNullException(nameof(config.HttpBaseUrl));

        if (string.IsNullOrWhiteSpace(config.Http2BaseUrl))
            throw new ArgumentNullException(nameof(config.Http2BaseUrl));

        var apiExplorerOptions = app.Services.GetService<IOptions<ApiExplorerOptions>>();

        var permissionEndpoints = (app as IEndpointRouteBuilder).DataSources
                                                                .SelectMany(t => t.Endpoints)
                                                                .Cast<RouteEndpoint>()
                                                                .Where(t => t.Metadata.Count > 0

                                                                            // && t.Metadata.GetMetadata<PermissionAttribute>() != null
                                                                         && t.Metadata.GetMetadata<HttpMethodMetadata>() != null
                                                                         && !string.IsNullOrWhiteSpace(t.RoutePattern.RawText))
                                                                .Select(t =>
                                                                        {
                                                                            var permissionAttr = t.Metadata.GetMetadata<PermissionAttribute>();
                                                                            var httpMethodAttr = t.Metadata.GetMetadata<HttpMethodMetadata>()!;
                                                                            var controllerActionDescriptor = t.Metadata.GetMetadata<ControllerActionDescriptor>();
                                                                            var grpcMethodMetadata = t.Metadata.GetMetadata<GrpcMethodMetadata>();
                                                                            var allowAnonymousAttr = t.Metadata.GetMetadata<AllowAnonymousAttribute>();

                                                                            return new PermissionEndpoint
                                                                                   {
                                                                                       Group = string.IsNullOrWhiteSpace(config.RouteGroupName) ? Assembly.GetEntryAssembly()!.GetName().Name! : config.RouteGroupName,
                                                                                       Protocol = grpcMethodMetadata == null ? HttpProtocols.Http1.ToString() : HttpProtocols.Http2.ToString(),
                                                                                       HttpMethod = httpMethodAttr.HttpMethods[0],
                                                                                       BaseUrl = (grpcMethodMetadata == null ? config.HttpBaseUrl : config.Http2BaseUrl).TrimEnd(char.Parse("/")),
                                                                                       RelativePath = GetRelativePath(t, apiExplorerOptions?.Value)!,
                                                                                       Template = TrimSlash(t.RoutePattern.RawText)!,
                                                                                       RouteValues = new Dictionary<string, string?>(t.RoutePattern.RequiredValues.Select(t2 => new KeyValuePair<string, string?>(t2.Key, t2.Value?.ToString()))),
                                                                                       FunctionId = permissionAttr?.FunctionId ?? "OTHER",
                                                                                       NativePermission = (permissionAttr?.NativePermission ?? GetPermission(httpMethodAttr)) | GetPermission(controllerActionDescriptor) | GetPermission(grpcMethodMetadata),
                                                                                       AllowAnonymous = allowAnonymousAttr != null || permissionAttr == null,
                                                                                       Tag = permissionAttr?.Tag
                                                                                   };
                                                                        })
                                                                .Where(t => handler?.Invoke(scope.ServiceProvider, t) ?? true)
                                                                .Union(otherPermissionEndpoints ?? Array.Empty<PermissionEndpoint>())
                                                                .ToArray();

        using var channel = GrpcChannel.ForAddress(config.RouteServiceUrl);

        var client = new RouteService.RouteServiceClient(channel);

        var request = new RegisterRouteRequest
                      {
                          Groups =
                          {
                              permissionEndpoints.GroupBy(t => $"{t.Group} - {t.Protocol}")
                                                 .Select(t => new RegisterRouteRequest.Types.RouteGroup
                                                              {
                                                                  Name = t.Key,
                                                                  BaseUrl = HttpProtocols.Http2.ToString().Equals(t.Key, StringComparison.OrdinalIgnoreCase)
                                                                                ? config.Http2BaseUrl
                                                                                : config.HttpBaseUrl,
                                                                  ForwarderRequestVersion = config.ForwarderRequestVersion,
                                                                  ForwarderHttpVersionPolicy = config.ForwarderHttpVersionPolicy.HasValue ? (int)config.ForwarderHttpVersionPolicy.Value : null,
                                                                  ForwarderActivityTimeout = config.ForwarderActivityTimeout.HasValue ? Duration.FromTimeSpan(config.ForwarderActivityTimeout.Value) : null,
                                                                  ForwarderAllowResponseBuffering = config.ForwarderAllowResponseBuffering,
                                                                  Routes =
                                                                  {
                                                                      t.Select(t2 => new RegisterRouteRequest.Types.Route
                                                                                     {
                                                                                         Protocol = t2.Protocol,
                                                                                         HttpMethod = t2.HttpMethod,
                                                                                         RelativePath = t2.RelativePath,
                                                                                         Template = t2.Template,
                                                                                         FunctionId = t2.FunctionId,
                                                                                         NativePermission = t2.NativePermission.FromPermissionType<Netcorext.Auth.Protobufs.Enums.PermissionType>(),
                                                                                         AllowAnonymous = t2.AllowAnonymous,
                                                                                         Tag = t2.Tag,
                                                                                         RouteValues =
                                                                                         {
                                                                                             t2.RouteValues.Select(t3 => new RegisterRouteRequest.Types.RouteValue
                                                                                                                         {
                                                                                                                             Key = t3.Key,
                                                                                                                             Value = t3.Value
                                                                                                                         })
                                                                                         }
                                                                                     })
                                                                  }
                                                              })
                          }
                      };

        try
        {
            client.RegisterRoute(request);
        }
        catch (Exception e)
        {
            logger.LogError(e, "{E}", e);
        }

        return builder;
    }

    private static PermissionType GetPermission(HttpMethodMetadata? meta)
    {
        if (meta == null) return PermissionType.None;

        return meta.HttpMethods.Aggregate(PermissionType.None, (current, method) => current | method switch
                                                                                              {
                                                                                                  "GET" => PermissionType.Read,
                                                                                                  "POST" => PermissionType.Write,
                                                                                                  "PUT" => PermissionType.Write,
                                                                                                  "PATCH" => PermissionType.Write,
                                                                                                  "DELETE" => PermissionType.Delete,
                                                                                                  _ => PermissionType.None
                                                                                              });
    }

    private static PermissionType GetPermission(ControllerActionDescriptor? meta)
    {
        if (meta == null) return PermissionType.None;

        return meta.EndpointMetadata.FirstOrDefault(t => t is HttpMethodMetadata) is not HttpMethodMetadata httpMethodMetadata ? GetPermission(meta.ActionName) : GetPermission(httpMethodMetadata);
    }

    private static PermissionType GetPermission(GrpcMethodMetadata? meta)
    {
        return meta == null ? PermissionType.None : GetPermission(meta.Method.Name);
    }

    private static PermissionType GetPermission(string methodName)
    {
        if (methodName.StartsWith("Get")) return PermissionType.Read;
        if (methodName.StartsWith("Query")) return PermissionType.Read;
        if (methodName.StartsWith("Post")) return PermissionType.Write;
        if (methodName.StartsWith("Put")) return PermissionType.Write;
        if (methodName.StartsWith("Patch")) return PermissionType.Write;
        if (methodName.StartsWith("Create")) return PermissionType.Write;
        if (methodName.StartsWith("Update")) return PermissionType.Write;
        if (methodName.StartsWith("Reset")) return PermissionType.Write;
        if (methodName.StartsWith("Delete")) return PermissionType.Delete;
        if (methodName.StartsWith("Remove")) return PermissionType.Delete;
        if (methodName.StartsWith("Clear")) return PermissionType.Delete;

        return PermissionType.None;
    }

    private static string? GetRelativePath(RouteEndpoint routeEndpoint, ApiExplorerOptions? options)
    {
        var apiVersionAttr = routeEndpoint.Metadata.GetMetadata<ApiVersionAttribute>();
        var apiVersion = apiVersionAttr == null ? options?.DefaultApiVersion : apiVersionAttr.Versions[0];
        var rawText = TrimSlash(routeEndpoint.RoutePattern.RawText);

        if (string.IsNullOrWhiteSpace(rawText) || !RegexRoutePattern.IsMatch(rawText)) return rawText;

        var version = apiVersion?.ToString(options?.SubstitutionFormat ?? "VVV") ?? "";

        rawText = RegexRoutePattern.Replace(rawText, version);

        return rawText;
    }

    private static string? TrimSlash(string? text)
    {
        return text?.Trim(char.Parse("/"));
    }
}