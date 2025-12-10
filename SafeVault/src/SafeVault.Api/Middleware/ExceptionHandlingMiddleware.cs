using System.Text.Json;

namespace SafeVault.Api.Middleware;

/// <summary>
/// Global exception handling middleware.
/// 
/// SECURITY CONSIDERATIONS:
/// - Never expose stack traces or internal error details to clients
/// - Log full error details for debugging
/// - Return generic error messages to prevent information disclosure
/// - Use correlation IDs for tracking issues
/// </summary>
public class ExceptionHandlingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ExceptionHandlingMiddleware> _logger;

    public ExceptionHandlingMiddleware(RequestDelegate next, ILogger<ExceptionHandlingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            await HandleExceptionAsync(context, ex);
        }
    }

    private async Task HandleExceptionAsync(HttpContext context, Exception exception)
    {
        // Generate a correlation ID for tracking
        var correlationId = Guid.NewGuid().ToString();

        // SECURITY: Log full details internally, but don't expose to client
        _logger.LogError(exception, 
            "Unhandled exception occurred. CorrelationId: {CorrelationId}, Path: {Path}, Method: {Method}",
            correlationId, context.Request.Path, context.Request.Method);

        context.Response.ContentType = "application/json";
        context.Response.StatusCode = StatusCodes.Status500InternalServerError;

        // SECURITY: Return generic error message - don't expose internal details
        var errorResponse = new
        {
            Error = "An unexpected error occurred",
            CorrelationId = correlationId,
            // SECURITY: Only include timestamp, not exception details
            Timestamp = DateTime.UtcNow
        };

        var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        await context.Response.WriteAsync(JsonSerializer.Serialize(errorResponse, options));
    }
}

/// <summary>
/// Extension method to add the exception handling middleware.
/// </summary>
public static class ExceptionHandlingMiddlewareExtensions
{
    public static IApplicationBuilder UseGlobalExceptionHandler(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<ExceptionHandlingMiddleware>();
    }
}
