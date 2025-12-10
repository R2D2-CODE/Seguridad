using Microsoft.EntityFrameworkCore;
using SafeVault.Core.Entities;

namespace SafeVault.Infrastructure.Data;

/// <summary>
/// Entity Framework Core DbContext for SafeVault.
/// Configured to use parameterized queries by default, preventing SQL injection.
/// </summary>
public class SafeVaultDbContext : DbContext
{
    public SafeVaultDbContext(DbContextOptions<SafeVaultDbContext> options) 
        : base(options)
    {
    }
    
    /// <summary>
    /// Users table - contains authenticated user data.
    /// </summary>
    public DbSet<User> Users => Set<User>();
    
    /// <summary>
    /// VaultItems table - contains secure vault data.
    /// </summary>
    public DbSet<VaultItem> VaultItems => Set<VaultItem>();
    
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        
        // Configure User entity
        modelBuilder.Entity<User>(entity =>
        {
            entity.HasKey(e => e.Id);
            
            entity.Property(e => e.Username)
                .IsRequired()
                .HasMaxLength(50);
            
            entity.Property(e => e.Email)
                .IsRequired()
                .HasMaxLength(100);
            
            entity.Property(e => e.PasswordHash)
                .IsRequired()
                .HasMaxLength(255);
            
            entity.Property(e => e.Role)
                .IsRequired()
                .HasMaxLength(20);
            
            // Create unique indexes for username and email
            entity.HasIndex(e => e.Username).IsUnique();
            entity.HasIndex(e => e.Email).IsUnique();
        });
        
        // Configure VaultItem entity
        modelBuilder.Entity<VaultItem>(entity =>
        {
            entity.HasKey(e => e.Id);
            
            entity.Property(e => e.Title)
                .IsRequired()
                .HasMaxLength(200);
            
            entity.Property(e => e.Content)
                .IsRequired()
                .HasMaxLength(10000);
            
            entity.Property(e => e.Category)
                .HasMaxLength(100);
            
            // Configure foreign key relationship
            entity.HasOne(e => e.User)
                .WithMany()
                .HasForeignKey(e => e.UserId)
                .OnDelete(DeleteBehavior.Cascade);
            
            // Create index for faster user-based queries
            entity.HasIndex(e => e.UserId);
        });
    }
}
