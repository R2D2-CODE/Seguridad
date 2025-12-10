using SafeVault.Core.Entities;

namespace SafeVault.Core.Interfaces;

/// <summary>
/// Repository interface for VaultItem operations.
/// All implementations must use parameterized queries to prevent SQL injection.
/// </summary>
public interface IVaultRepository
{
    /// <summary>
    /// Gets a vault item by its unique identifier.
    /// Uses parameterized query internally.
    /// </summary>
    Task<VaultItem?> GetByIdAsync(int id);
    
    /// <summary>
    /// Gets all vault items for a specific user.
    /// Uses parameterized query with userId parameter.
    /// </summary>
    Task<IEnumerable<VaultItem>> GetByUserIdAsync(int userId);
    
    /// <summary>
    /// Searches vault items by title for a specific user.
    /// Uses parameterized query - NEVER concatenate search terms directly.
    /// </summary>
    Task<IEnumerable<VaultItem>> SearchByTitleAsync(int userId, string searchTerm);
    
    /// <summary>
    /// Creates a new vault item.
    /// Content is sanitized before storage.
    /// </summary>
    Task<VaultItem> CreateAsync(VaultItem item);
    
    /// <summary>
    /// Updates an existing vault item.
    /// Content is sanitized before storage.
    /// </summary>
    Task<VaultItem> UpdateAsync(VaultItem item);
    
    /// <summary>
    /// Deletes a vault item by its identifier.
    /// Uses parameterized query internally.
    /// </summary>
    Task<bool> DeleteAsync(int id);
}
