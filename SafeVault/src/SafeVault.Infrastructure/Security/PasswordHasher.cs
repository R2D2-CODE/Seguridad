using SafeVault.Core.Interfaces;

namespace SafeVault.Infrastructure.Security;

/// <summary>
/// Secure password hashing implementation using BCrypt.
/// 
/// BCrypt is a password hashing function designed to be computationally expensive,
/// making brute-force attacks impractical. It automatically handles salt generation
/// and includes the salt in the resulting hash.
/// 
/// SECURITY FEATURES:
/// - Adaptive cost factor (work factor) that can be increased as hardware improves
/// - Built-in salt generation (128-bit random salt)
/// - Constant-time comparison to prevent timing attacks
/// - Resistant to rainbow table attacks due to per-password salts
/// </summary>
public class PasswordHasher : IPasswordHasher
{
    // Work factor: 12 means 2^12 = 4096 iterations
    // Higher = more secure but slower. 12 is a good balance for 2024.
    private const int WorkFactor = 12;
    
    /// <summary>
    /// Hashes a password using BCrypt with automatic salt generation.
    /// 
    /// The resulting hash includes:
    /// - Algorithm identifier ($2a$)
    /// - Work factor
    /// - 128-bit salt
    /// - 184-bit hash
    /// 
    /// Example output: $2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.F3XUG7Yq3Qx5
    /// </summary>
    public string HashPassword(string password)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("Password cannot be null or empty", nameof(password));
        
        // BCrypt.HashPassword automatically generates a cryptographically secure salt
        return BCrypt.Net.BCrypt.HashPassword(password, WorkFactor);
    }
    
    /// <summary>
    /// Verifies a password against a stored BCrypt hash.
    /// 
    /// Uses constant-time comparison to prevent timing attacks.
    /// A timing attack could potentially reveal information about the hash
    /// by measuring how long the comparison takes.
    /// </summary>
    public bool VerifyPassword(string password, string hash)
    {
        if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(hash))
            return false;
        
        try
        {
            // BCrypt.Verify uses constant-time comparison internally
            return BCrypt.Net.BCrypt.Verify(password, hash);
        }
        catch
        {
            // If the hash format is invalid, return false rather than throwing
            return false;
        }
    }
}
