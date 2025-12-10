using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Core.Entities;
using SafeVault.Core.Interfaces;

namespace SafeVault.Api.Controllers;

/// <summary>
/// Admin controller for user management.
/// All endpoints require Admin role (RBAC).
/// 
/// SECURITY: Demonstrates Role-Based Access Control (RBAC)
/// - Only users with Admin role can access these endpoints
/// - Attempted access by non-admins is logged and rejected
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize(Roles = Roles.Admin)] // RBAC: Only Admin role can access
public class AdminController : ControllerBase
{
    private readonly IUserRepository _userRepository;
    private readonly ILogger<AdminController> _logger;

    public AdminController(
        IUserRepository userRepository,
        ILogger<AdminController> logger)
    {
        _userRepository = userRepository;
        _logger = logger;
    }

    /// <summary>
    /// Gets all users in the system.
    /// Admin only - demonstrates RBAC.
    /// </summary>
    [HttpGet("users")]
    public async Task<ActionResult<IEnumerable<object>>> GetAllUsers()
    {
        _logger.LogInformation("Admin accessed user list");

        var users = await _userRepository.GetAllAsync();

        // SECURITY: Never return password hashes to the client
        return Ok(users.Select(u => new
        {
            u.Id,
            u.Username,
            u.Email,
            u.Role,
            u.CreatedAt,
            u.IsActive
        }));
    }

    /// <summary>
    /// Gets a specific user by ID.
    /// Admin only.
    /// </summary>
    [HttpGet("users/{id:int}")]
    public async Task<ActionResult<object>> GetUser(int id)
    {
        var user = await _userRepository.GetByIdAsync(id);
        
        if (user == null)
        {
            return NotFound();
        }

        // SECURITY: Never return password hash
        return Ok(new
        {
            user.Id,
            user.Username,
            user.Email,
            user.Role,
            user.CreatedAt,
            user.IsActive
        });
    }

    /// <summary>
    /// Updates a user's role.
    /// Admin only - demonstrates RBAC modification.
    /// </summary>
    [HttpPatch("users/{id:int}/role")]
    public async Task<ActionResult> UpdateUserRole(int id, [FromBody] UpdateRoleRequest request)
    {
        if (!Roles.AllRoles.Contains(request.Role))
        {
            return BadRequest(new { Error = "Invalid role" });
        }

        var user = await _userRepository.GetByIdAsync(id);
        if (user == null)
        {
            return NotFound();
        }

        var oldRole = user.Role;
        user.Role = request.Role;

        await _userRepository.UpdateAsync(user);

        _logger.LogInformation("Admin changed user {UserId} role from {OldRole} to {NewRole}",
            id, oldRole, request.Role);

        return Ok(new { Message = $"User role updated to {request.Role}" });
    }

    /// <summary>
    /// Activates or deactivates a user account.
    /// Admin only.
    /// </summary>
    [HttpPatch("users/{id:int}/status")]
    public async Task<ActionResult> UpdateUserStatus(int id, [FromBody] UpdateStatusRequest request)
    {
        var user = await _userRepository.GetByIdAsync(id);
        if (user == null)
        {
            return NotFound();
        }

        user.IsActive = request.IsActive;
        await _userRepository.UpdateAsync(user);

        _logger.LogInformation("Admin {Action} user {UserId}",
            request.IsActive ? "activated" : "deactivated", id);

        return Ok(new { Message = $"User {(request.IsActive ? "activated" : "deactivated")}" });
    }

    /// <summary>
    /// Security dashboard - shows system security status.
    /// Admin only.
    /// </summary>
    [HttpGet("security/dashboard")]
    public async Task<ActionResult<object>> GetSecurityDashboard()
    {
        var users = await _userRepository.GetAllAsync();
        var userList = users.ToList();

        return Ok(new
        {
            TotalUsers = userList.Count,
            ActiveUsers = userList.Count(u => u.IsActive),
            InactiveUsers = userList.Count(u => !u.IsActive),
            AdminUsers = userList.Count(u => u.Role == Roles.Admin),
            RegularUsers = userList.Count(u => u.Role == Roles.User),
            SecurityFeatures = new
            {
                PasswordHashing = "BCrypt with work factor 12",
                Authentication = "JWT Bearer tokens (1 hour expiry)",
                Authorization = "Role-Based Access Control (RBAC)",
                InputValidation = "FluentValidation with XSS/SQLi pattern detection",
                DataAccess = "Entity Framework Core with parameterized queries",
                XssPrevention = "HtmlSanitizer for all user content"
            }
        });
    }
}

/// <summary>
/// Request model for updating user role.
/// </summary>
public record UpdateRoleRequest
{
    public required string Role { get; init; }
}

/// <summary>
/// Request model for updating user status.
/// </summary>
public record UpdateStatusRequest
{
    public required bool IsActive { get; init; }
}
