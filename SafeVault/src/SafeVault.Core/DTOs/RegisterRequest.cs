namespace SafeVault.Core.DTOs;

/// <summary>
/// DTO for user registration requests.
/// All fields are validated and sanitized to prevent security vulnerabilities.
/// </summary>
public record RegisterRequest
{
    /// <summary>
    /// Username for the new account.
    /// Validated for: required, length limits (3-50 chars), alphanumeric only.
    /// </summary>
    public required string Username { get; init; }
    
    /// <summary>
    /// Email address for the new account.
    /// Validated for: required, valid email format.
    /// </summary>
    public required string Email { get; init; }
    
    /// <summary>
    /// Password for the new account.
    /// Validated for: required, minimum 8 characters, complexity requirements.
    /// Will be hashed before storage - NEVER stored in plain text.
    /// </summary>
    public required string Password { get; init; }
    
    /// <summary>
    /// Password confirmation to prevent typos.
    /// Must match Password field.
    /// </summary>
    public required string ConfirmPassword { get; init; }
}
