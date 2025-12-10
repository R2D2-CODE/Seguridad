namespace SafeVault.Api.Middleware;

/// <summary>
/// Middleware to add security headers to all HTTP responses.
/// These headers help protect against common web vulnerabilities.
/// 
/// SECURITY HEADERS IMPLEMENTED:
/// - X-Content-Type-Options: Prevents MIME type sniffing
/// - X-Frame-Options: Prevents clickjacking attacks
/// - X-XSS-Protection: Enables browser's XSS filter (legacy)
/// - Content-Security-Policy: Controls resource loading
/// - Referrer-Policy: Controls referrer information
/// - Permissions-Policy: Controls browser features
/// - Strict-Transport-Security: Enforces HTTPS (HSTS)
/// - Cache-Control: Prevents caching of sensitive data
/// </summary>
public class SecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<SecurityHeadersMiddleware> _logger;

    public SecurityHeadersMiddleware(RequestDelegate next, ILogger<SecurityHeadersMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Add security headers before the response is sent
        context.Response.OnStarting(() =>
        {
            var headers = context.Response.Headers;

            // Prevent MIME type sniffing - stops browser from interpreting files as different MIME types
            headers["X-Content-Type-Options"] = "nosniff";

            // Prevent clickjacking - stops the page from being embedded in iframes
            headers["X-Frame-Options"] = "DENY";

            // XSS Protection - enables browser's built-in XSS filter (legacy, but still useful)
            headers["X-XSS-Protection"] = "1; mode=block";

            // Content Security Policy - controls what resources can be loaded
            // This is a strict policy that only allows resources from the same origin
            headers["Content-Security-Policy"] = 
                "default-src 'self'; " +
                "script-src 'self'; " +
                "style-src 'self' 'unsafe-inline'; " +
                "img-src 'self' data:; " +
                "font-src 'self'; " +
                "form-action 'self'; " +
                "frame-ancestors 'none'; " +
                "base-uri 'self';";

            // Referrer Policy - controls how much referrer information is sent
            headers["Referrer-Policy"] = "strict-origin-when-cross-origin";

            // Permissions Policy - controls browser features
            headers["Permissions-Policy"] = 
                "accelerometer=(), camera=(), geolocation=(), gyroscope=(), " +
                "magnetometer=(), microphone=(), payment=(), usb=()";

            // HSTS - enforces HTTPS connections (only in production)
            if (!context.Request.Host.Host.Contains("localhost"))
            {
                headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
            }

            // Prevent caching of sensitive API responses
            if (context.Request.Path.StartsWithSegments("/api"))
            {
                headers["Cache-Control"] = "no-store, no-cache, must-revalidate, proxy-revalidate";
                headers["Pragma"] = "no-cache";
                headers["Expires"] = "0";
            }

            return Task.CompletedTask;
        });

        await _next(context);
    }
}

/// <summary>
/// Extension method to easily add the security headers middleware.
/// </summary>
public static class SecurityHeadersMiddlewareExtensions
{
    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<SecurityHeadersMiddleware>();
    }
}
