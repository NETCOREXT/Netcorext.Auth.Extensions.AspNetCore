namespace Netcorext.Auth.Extensions.AspNetCore.Settings;

public class RegisterConfig
{
    public string? RouteGroupName { get; set; }
    public string RouteServiceUrl { get; set; } = null!;
    public string HttpBaseUrl { get; set; } = null!;
    public string Http2BaseUrl { get; set; } = null!;
    public string? ForwarderRequestVersion { get; set; }
    public HttpVersionPolicy? ForwarderHttpVersionPolicy { get; set; }
    public TimeSpan? ForwarderActivityTimeout { get; set; }
    public bool? ForwarderAllowResponseBuffering { get; set; }
}