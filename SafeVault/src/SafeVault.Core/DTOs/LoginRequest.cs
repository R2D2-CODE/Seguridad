namespace SafeVault.Core.DTOs;

/// <summary>
/// DTO for user login requests.
/// All fields are validated before processing to prevent injection attacks.
/// </summary>
public record LoginRequest
{
    /// <summary>
    /// Username for authentication.
    /// Validated for: required, length limits, no malicious characters.
    /// </summary>
    public required string Username { get; init; }
    
    /// <summary>
    /// Password for authentication.
    /// Validated for: required, minimum length.
    /// NEVER logged or stored in plain text.
    /// </summary>
    public required string Password { get; init; }
}
