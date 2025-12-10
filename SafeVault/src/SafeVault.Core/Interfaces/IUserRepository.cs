using SafeVault.Core.Entities;

namespace SafeVault.Core.Interfaces;

/// <summary>
/// Repository interface for User operations.
/// All implementations must use parameterized queries to prevent SQL injection.
/// </summary>
public interface IUserRepository
{
    /// <summary>
    /// Gets a user by their unique identifier.
    /// Uses parameterized query internally.
    /// </summary>
    Task<User?> GetByIdAsync(int id);
    
    /// <summary>
    /// Gets a user by their username.
    /// Uses parameterized query internally to prevent SQL injection.
    /// </summary>
    Task<User?> GetByUsernameAsync(string username);
    
    /// <summary>
    /// Gets a user by their email address.
    /// Uses parameterized query internally.
    /// </summary>
    Task<User?> GetByEmailAsync(string email);
    
    /// <summary>
    /// Creates a new user in the database.
    /// Password must be hashed before calling this method.
    /// </summary>
    Task<User> CreateAsync(User user);
    
    /// <summary>
    /// Updates an existing user.
    /// </summary>
    Task<User> UpdateAsync(User user);
    
    /// <summary>
    /// Checks if a username already exists.
    /// </summary>
    Task<bool> UsernameExistsAsync(string username);
    
    /// <summary>
    /// Checks if an email already exists.
    /// </summary>
    Task<bool> EmailExistsAsync(string email);
    
    /// <summary>
    /// Gets all users (Admin only operation).
    /// </summary>
    Task<IEnumerable<User>> GetAllAsync();
}
