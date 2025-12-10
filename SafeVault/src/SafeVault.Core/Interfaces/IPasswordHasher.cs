namespace SafeVault.Core.Interfaces;

/// <summary>
/// Interface for secure password hashing operations.
/// Implementations should use strong hashing algorithms like BCrypt or Argon2.
/// </summary>
public interface IPasswordHasher
{
    /// <summary>
    /// Hashes a plain text password using a secure algorithm.
    /// The resulting hash includes the salt and algorithm parameters.
    /// </summary>
    /// <param name="password">Plain text password to hash.</param>
    /// <returns>Secure hash string including salt and algorithm info.</returns>
    string HashPassword(string password);
    
    /// <summary>
    /// Verifies a plain text password against a stored hash.
    /// Uses constant-time comparison to prevent timing attacks.
    /// </summary>
    /// <param name="password">Plain text password to verify.</param>
    /// <param name="hash">Stored hash to compare against.</param>
    /// <returns>True if password matches, false otherwise.</returns>
    bool VerifyPassword(string password, string hash);
}
