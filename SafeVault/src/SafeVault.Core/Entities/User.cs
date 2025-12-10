namespace SafeVault.Core.Entities;

/// <summary>
/// Represents a user in the SafeVault system.
/// Implements secure password storage using hashed passwords.
/// </summary>
public class User
{
    public int Id { get; set; }
    
    /// <summary>
    /// Username - validated and sanitized to prevent injection attacks.
    /// </summary>
    public required string Username { get; set; }
    
    /// <summary>
    /// Email address - validated for proper format.
    /// </summary>
    public required string Email { get; set; }
    
    /// <summary>
    /// Password hash - NEVER store plain text passwords.
    /// Uses BCrypt for secure hashing.
    /// </summary>
    public required string PasswordHash { get; set; }
    
    /// <summary>
    /// User's role for RBAC (Role-Based Access Control).
    /// </summary>
    public required string Role { get; set; }
    
    /// <summary>
    /// Date when the user was created.
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    /// <summary>
    /// Indicates if the user account is active.
    /// </summary>
    public bool IsActive { get; set; } = true;
}
