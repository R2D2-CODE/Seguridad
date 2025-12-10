namespace SafeVault.Core.DTOs;

/// <summary>
/// Response returned after successful authentication.
/// Contains JWT token for subsequent API calls.
/// </summary>
public record AuthResponse
{
    /// <summary>
    /// JWT access token for authenticating API requests.
    /// Should be included in Authorization header as "Bearer {token}".
    /// </summary>
    public required string Token { get; init; }
    
    /// <summary>
    /// Token expiration time in UTC.
    /// Client should refresh or re-authenticate before expiration.
    /// </summary>
    public required DateTime ExpiresAt { get; init; }
    
    /// <summary>
    /// Authenticated user's username.
    /// </summary>
    public required string Username { get; init; }
    
    /// <summary>
    /// User's role for client-side authorization decisions.
    /// </summary>
    public required string Role { get; init; }
}
