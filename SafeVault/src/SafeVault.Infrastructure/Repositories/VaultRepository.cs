using Microsoft.EntityFrameworkCore;
using SafeVault.Core.Entities;
using SafeVault.Core.Interfaces;
using SafeVault.Infrastructure.Data;

namespace SafeVault.Infrastructure.Repositories;

/// <summary>
/// Repository implementation for VaultItem operations.
/// Uses Entity Framework Core with parameterized queries to prevent SQL injection.
/// 
/// SECURITY: All queries use LINQ which generates parameterized SQL.
/// Content is sanitized before storage to prevent XSS attacks.
/// </summary>
public class VaultRepository : IVaultRepository
{
    private readonly SafeVaultDbContext _context;
    private readonly IInputSanitizer _sanitizer;
    
    public VaultRepository(SafeVaultDbContext context, IInputSanitizer sanitizer)
    {
        _context = context;
        _sanitizer = sanitizer;
    }
    
    /// <summary>
    /// Gets a vault item by ID using parameterized query.
    /// </summary>
    public async Task<VaultItem?> GetByIdAsync(int id)
    {
        // SECURE: EF Core uses parameterized query
        return await _context.VaultItems
            .AsNoTracking()
            .FirstOrDefaultAsync(v => v.Id == id);
    }
    
    /// <summary>
    /// Gets all vault items for a specific user.
    /// Uses parameterized query with userId parameter.
    /// </summary>
    public async Task<IEnumerable<VaultItem>> GetByUserIdAsync(int userId)
    {
        // SECURE: userId is parameterized
        return await _context.VaultItems
            .AsNoTracking()
            .Where(v => v.UserId == userId)
            .OrderByDescending(v => v.CreatedAt)
            .ToListAsync();
    }
    
    /// <summary>
    /// Searches vault items by title for a specific user.
    /// 
    /// SECURITY: Uses EF.Functions.Like with parameterized values.
    /// NEVER concatenate search terms directly into queries.
    /// 
    /// INSECURE EXAMPLE (NEVER DO THIS):
    /// var query = $"SELECT * FROM VaultItems WHERE Title LIKE '%{searchTerm}%'";
    /// </summary>
    public async Task<IEnumerable<VaultItem>> SearchByTitleAsync(int userId, string searchTerm)
    {
        // Sanitize search term first
        var sanitizedTerm = _sanitizer.SanitizePlainText(searchTerm);
        
        // SECURE: Both userId and searchTerm are parameterized
        return await _context.VaultItems
            .AsNoTracking()
            .Where(v => v.UserId == userId && 
                       EF.Functions.Like(v.Title, $"%{sanitizedTerm}%"))
            .OrderByDescending(v => v.CreatedAt)
            .ToListAsync();
    }
    
    /// <summary>
    /// Creates a new vault item.
    /// Content is sanitized before storage to prevent XSS.
    /// </summary>
    public async Task<VaultItem> CreateAsync(VaultItem item)
    {
        // SECURITY: Sanitize content before storage to prevent stored XSS
        item.Title = _sanitizer.SanitizeHtml(item.Title);
        item.Content = _sanitizer.SanitizeHtml(item.Content);
        item.Category = _sanitizer.SanitizeHtml(item.Category);
        item.CreatedAt = DateTime.UtcNow;
        
        // SECURE: EF Core uses parameterized INSERT
        _context.VaultItems.Add(item);
        await _context.SaveChangesAsync();
        return item;
    }
    
    /// <summary>
    /// Updates an existing vault item.
    /// Content is sanitized before storage to prevent XSS.
    /// </summary>
    public async Task<VaultItem> UpdateAsync(VaultItem item)
    {
        // SECURITY: Sanitize content before storage
        item.Title = _sanitizer.SanitizeHtml(item.Title);
        item.Content = _sanitizer.SanitizeHtml(item.Content);
        item.Category = _sanitizer.SanitizeHtml(item.Category);
        item.UpdatedAt = DateTime.UtcNow;
        
        // SECURE: EF Core uses parameterized UPDATE
        _context.VaultItems.Update(item);
        await _context.SaveChangesAsync();
        return item;
    }
    
    /// <summary>
    /// Deletes a vault item by ID.
    /// Uses parameterized query for the ID lookup.
    /// </summary>
    public async Task<bool> DeleteAsync(int id)
    {
        // SECURE: id is parameterized
        var item = await _context.VaultItems.FindAsync(id);
        if (item == null) return false;
        
        _context.VaultItems.Remove(item);
        await _context.SaveChangesAsync();
        return true;
    }
}
