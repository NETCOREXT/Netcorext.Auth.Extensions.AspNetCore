using System.Reflection;
using System.Text.RegularExpressions;
using Grpc.AspNetCore.Server;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Options;
using Netcorext.Auth;
using Netcorext.Auth.Attributes;
using Netcorext.Auth.Enums;

namespace Microsoft.Extensions.DependencyInjection;

public static class ApplicationBuilderExtension
{
    private static readonly Regex RegexRoutePattern = new Regex(@"\{([^:]+):apiVersion\}", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static IApplicationBuilder RegisterPermissionEndpoints(this IApplicationBuilder builder, string httpsBaseUrl = "https://localhost", string grpcBaseUrl = "https://localhost:8080") => RegisterPermissionEndpoints(builder, null, httpsBaseUrl, grpcBaseUrl);

    public static IApplicationBuilder RegisterPermissionEndpoints(this IApplicationBuilder builder, Action<IServiceProvider, IEnumerable<PermissionEndpoint>>? configure, string httpsBaseUrl = "https://localhost", string grpcBaseUrl = "https://localhost:8080")
    {
        var app = (WebApplication)builder;

        var apiExplorerOptions = app.Services.GetService<IOptions<ApiExplorerOptions>>();

        var routeEndpoints = (app as IEndpointRouteBuilder).DataSources
                                                           .SelectMany(t => t.Endpoints)
                                                           .Cast<RouteEndpoint>()
                                                           .Where(t => t.Metadata.Count > 0
                                                                    // && t.Metadata.GetMetadata<PermissionAttribute>() != null
                                                                    && t.Metadata.GetMetadata<HttpMethodMetadata>() != null
                                                                    && !string.IsNullOrWhiteSpace(t.RoutePattern.RawText))
                                                           .ToArray();

        var permissionEndpoints = routeEndpoints.Select(t =>
                                                        {
                                                            var permissionAttr = t.Metadata.GetMetadata<PermissionAttribute>();
                                                            var httpMethodAttr = t.Metadata.GetMetadata<HttpMethodMetadata>()!;
                                                            var controllerActionDescriptor = t.Metadata.GetMetadata<ControllerActionDescriptor>();
                                                            var grpcMethodMetadata = t.Metadata.GetMetadata<GrpcMethodMetadata>();
                                                            var allowAnonymousAttr = t.Metadata.GetMetadata<AllowAnonymousAttribute>();
                                                            
                                                            return new PermissionEndpoint
                                                                   {
                                                                       Group = Assembly.GetEntryAssembly()!.GetName().Name!,
                                                                       Protocol = grpcMethodMetadata == null ? HttpProtocols.Http1.ToString() : HttpProtocols.Http2.ToString(),
                                                                       HttpMethod = httpMethodAttr.HttpMethods[0],
                                                                       BaseUrl = (grpcMethodMetadata == null ? httpsBaseUrl : grpcBaseUrl).TrimEnd(char.Parse("/")),
                                                                       RelativePath = GetRelativePath(t, apiExplorerOptions?.Value)!,
                                                                       Template = TrimSlash(t.RoutePattern.RawText)!,
                                                                       RouteValues = new Dictionary<string, string?>(t.RoutePattern.RequiredValues.Select(t2 => new KeyValuePair<string, string?>(t2.Key, t2.Value?.ToString()))),
                                                                       FunctionId = permissionAttr?.FunctionId ?? "OTHER",
                                                                       NativePermission = (permissionAttr?.NativePermission ?? GetPermission(httpMethodAttr)) | GetPermission(controllerActionDescriptor) | GetPermission(grpcMethodMetadata),
                                                                       AllowAnonymous = allowAnonymousAttr != null || permissionAttr == null,
                                                                       Tag = permissionAttr?.Tag
                                                                   };
                                                        });

        using var scope = app.Services.CreateScope();

        configure?.Invoke(scope.ServiceProvider, permissionEndpoints);

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