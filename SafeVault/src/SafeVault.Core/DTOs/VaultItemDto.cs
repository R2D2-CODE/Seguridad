namespace SafeVault.Core.DTOs;

/// <summary>
/// DTO for vault item operations.
/// All input is sanitized to prevent XSS attacks.
/// </summary>
public record VaultItemDto
{
    /// <summary>
    /// Unique identifier (only for responses, not required for creation).
    /// </summary>
    public int? Id { get; init; }
    
    /// <summary>
    /// Title of the vault item.
    /// Validated for: required, length limits, sanitized for XSS prevention.
    /// </summary>
    public required string Title { get; init; }
    
    /// <summary>
    /// Secure content to store.
    /// Validated for: required, sanitized for XSS prevention.
    /// </summary>
    public required string Content { get; init; }
    
    /// <summary>
    /// Optional category for organization.
    /// Sanitized for XSS prevention.
    /// </summary>
    public string? Category { get; init; }
}

/// <summary>
/// DTO for creating a new vault item.
/// </summary>
public record CreateVaultItemRequest
{
    /// <summary>
    /// Title of the vault item - sanitized for XSS.
    /// </summary>
    public required string Title { get; init; }
    
    /// <summary>
    /// Content to store securely - sanitized for XSS.
    /// </summary>
    public required string Content { get; init; }
    
    /// <summary>
    /// Optional category - sanitized for XSS.
    /// </summary>
    public string? Category { get; init; }
}

/// <summary>
/// DTO for updating an existing vault item.
/// </summary>
public record UpdateVaultItemRequest
{
    /// <summary>
    /// Updated title - sanitized for XSS.
    /// </summary>
    public required string Title { get; init; }
    
    /// <summary>
    /// Updated content - sanitized for XSS.
    /// </summary>
    public required string Content { get; init; }
    
    /// <summary>
    /// Updated category - sanitized for XSS.
    /// </summary>
    public string? Category { get; init; }
}
