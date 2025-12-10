using Microsoft.EntityFrameworkCore;
using SafeVault.Core.Entities;
using SafeVault.Core.Interfaces;
using SafeVault.Infrastructure.Data;

namespace SafeVault.Infrastructure.Repositories;

/// <summary>
/// Repository implementation for User operations.
/// Uses Entity Framework Core with parameterized queries to prevent SQL injection.
/// 
/// SECURITY: All queries use LINQ which generates parameterized SQL.
/// NEVER use string concatenation to build queries.
/// </summary>
public class UserRepository : IUserRepository
{
    private readonly SafeVaultDbContext _context;
    
    public UserRepository(SafeVaultDbContext context)
    {
        _context = context;
    }
    
    /// <summary>
    /// Gets a user by ID using parameterized query.
    /// EF Core generates: SELECT * FROM Users WHERE Id = @p0
    /// </summary>
    public async Task<User?> GetByIdAsync(int id)
    {
        // SECURE: EF Core uses parameterized queries
        return await _context.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Id == id);
    }
    
    /// <summary>
    /// Gets a user by username using parameterized query.
    /// EF Core generates: SELECT * FROM Users WHERE Username = @p0
    /// 
    /// SECURITY NOTE: The username parameter is never concatenated into the query.
    /// </summary>
    public async Task<User?> GetByUsernameAsync(string username)
    {
        // SECURE: Parameter 'username' is properly parameterized
        // INSECURE EXAMPLE (NEVER DO THIS):
        // var query = $"SELECT * FROM Users WHERE Username = '{username}'";
        
        return await _context.Users
            .FirstOrDefaultAsync(u => u.Username == username);
    }
    
    /// <summary>
    /// Gets a user by email using parameterized query.
    /// </summary>
    public async Task<User?> GetByEmailAsync(string email)
    {
        // SECURE: EF Core parameterizes the email value
        return await _context.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Email == email);
    }
    
    /// <summary>
    /// Creates a new user.
    /// Password should be hashed BEFORE calling this method.
    /// </summary>
    public async Task<User> CreateAsync(User user)
    {
        // SECURE: EF Core uses parameterized INSERT statement
        _context.Users.Add(user);
        await _context.SaveChangesAsync();
        return user;
    }
    
    /// <summary>
    /// Updates an existing user.
    /// </summary>
    public async Task<User> UpdateAsync(User user)
    {
        // SECURE: EF Core uses parameterized UPDATE statement
        _context.Users.Update(user);
        await _context.SaveChangesAsync();
        return user;
    }
    
    /// <summary>
    /// Checks if username exists using parameterized query.
    /// </summary>
    public async Task<bool> UsernameExistsAsync(string username)
    {
        // SECURE: Username is parameterized
        return await _context.Users
            .AsNoTracking()
            .AnyAsync(u => u.Username == username);
    }
    
    /// <summary>
    /// Checks if email exists using parameterized query.
    /// </summary>
    public async Task<bool> EmailExistsAsync(string email)
    {
        // SECURE: Email is parameterized
        return await _context.Users
            .AsNoTracking()
            .AnyAsync(u => u.Email == email);
    }
    
    /// <summary>
    /// Gets all users (Admin only).
    /// </summary>
    public async Task<IEnumerable<User>> GetAllAsync()
    {
        return await _context.Users
            .AsNoTracking()
            .ToListAsync();
    }
}
