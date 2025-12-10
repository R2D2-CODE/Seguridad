namespace SafeVault.Core.Entities;

/// <summary>
/// Represents a secure vault item containing sensitive data.
/// All content is sanitized before storage to prevent XSS attacks.
/// </summary>
public class VaultItem
{
    public int Id { get; set; }
    
    /// <summary>
    /// Title of the vault item - sanitized to prevent XSS.
    /// </summary>
    public required string Title { get; set; }
    
    /// <summary>
    /// Secure content - sanitized and stored securely.
    /// </summary>
    public required string Content { get; set; }
    
    /// <summary>
    /// Category for organization - sanitized input.
    /// </summary>
    public string? Category { get; set; }
    
    /// <summary>
    /// Foreign key to the user who owns this item.
    /// </summary>
    public int UserId { get; set; }
    
    /// <summary>
    /// Navigation property to the owner.
    /// </summary>
    public User? User { get; set; }
    
    /// <summary>
    /// Date when the item was created.
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    /// <summary>
    /// Date when the item was last modified.
    /// </summary>
    public DateTime? UpdatedAt { get; set; }
}
