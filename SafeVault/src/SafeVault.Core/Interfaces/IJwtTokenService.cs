using SafeVault.Core.Entities;

namespace SafeVault.Core.Interfaces;

/// <summary>
/// Interface for JWT token generation and validation.
/// </summary>
public interface IJwtTokenService
{
    /// <summary>
    /// Generates a JWT token for an authenticated user.
    /// Token includes user claims for authorization.
    /// </summary>
    /// <param name="user">Authenticated user.</param>
    /// <returns>JWT token string.</returns>
    string GenerateToken(User user);
    
    /// <summary>
    /// Gets the token expiration time.
    /// </summary>
    DateTime GetTokenExpiration();
}
