namespace SafeVault.Core.Entities;

/// <summary>
/// Defines the available roles in the SafeVault system.
/// Used for Role-Based Access Control (RBAC).
/// </summary>
public static class Roles
{
    /// <summary>
    /// Administrator role with full access to all features.
    /// </summary>
    public const string Admin = "Admin";
    
    /// <summary>
    /// Standard user role with limited access.
    /// </summary>
    public const string User = "User";
    
    /// <summary>
    /// Gets all available roles.
    /// </summary>
    public static readonly string[] AllRoles = [Admin, User];
}
