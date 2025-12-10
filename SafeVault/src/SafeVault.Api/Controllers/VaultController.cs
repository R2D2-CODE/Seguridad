using FluentValidation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Core.DTOs;
using SafeVault.Core.Entities;
using SafeVault.Core.Interfaces;

namespace SafeVault.Api.Controllers;

/// <summary>
/// Controller for managing secure vault items.
/// 
/// SECURITY FEATURES:
/// - Requires authentication for all operations
/// - User can only access their own vault items
/// - Admin can access all items
/// - All input is sanitized to prevent XSS
/// - All queries use parameterized statements to prevent SQL injection
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize] // Require authentication for all endpoints
public class VaultController : ControllerBase
{
    private readonly IVaultRepository _vaultRepository;
    private readonly IInputSanitizer _inputSanitizer;
    private readonly IValidator<CreateVaultItemRequest> _createValidator;
    private readonly IValidator<UpdateVaultItemRequest> _updateValidator;
    private readonly ILogger<VaultController> _logger;

    public VaultController(
        IVaultRepository vaultRepository,
        IInputSanitizer inputSanitizer,
        IValidator<CreateVaultItemRequest> createValidator,
        IValidator<UpdateVaultItemRequest> updateValidator,
        ILogger<VaultController> logger)
    {
        _vaultRepository = vaultRepository;
        _inputSanitizer = inputSanitizer;
        _createValidator = createValidator;
        _updateValidator = updateValidator;
        _logger = logger;
    }

    /// <summary>
    /// Gets all vault items for the authenticated user.
    /// </summary>
    [HttpGet]
    public async Task<ActionResult<IEnumerable<VaultItemDto>>> GetMyItems()
    {
        var userId = GetCurrentUserId();
        if (userId == null) return Unauthorized();

        // SECURITY: Query is parameterized - userId is never concatenated
        var items = await _vaultRepository.GetByUserIdAsync(userId.Value);

        return Ok(items.Select(MapToDto));
    }

    /// <summary>
    /// Gets a specific vault item by ID.
    /// Users can only access their own items (unless Admin).
    /// </summary>
    [HttpGet("{id:int}")]
    public async Task<ActionResult<VaultItemDto>> GetItem(int id)
    {
        var userId = GetCurrentUserId();
        if (userId == null) return Unauthorized();

        // SECURITY: ID is parameterized in the query
        var item = await _vaultRepository.GetByIdAsync(id);
        
        if (item == null)
        {
            return NotFound();
        }

        // SECURITY: Authorization check - users can only access their own items
        if (item.UserId != userId && !IsAdmin())
        {
            _logger.LogWarning("User {UserId} attempted to access item {ItemId} owned by {OwnerId}",
                userId, id, item.UserId);
            return Forbid();
        }

        return Ok(MapToDto(item));
    }

    /// <summary>
    /// Searches vault items by title.
    /// 
    /// SECURITY: Search term is sanitized and parameterized.
    /// Never concatenates user input into SQL queries.
    /// </summary>
    [HttpGet("search")]
    public async Task<ActionResult<IEnumerable<VaultItemDto>>> Search([FromQuery] string term)
    {
        var userId = GetCurrentUserId();
        if (userId == null) return Unauthorized();

        if (string.IsNullOrWhiteSpace(term))
        {
            return BadRequest(new { Error = "Search term is required" });
        }

        // SECURITY: Check for SQL injection patterns
        if (_inputSanitizer.ContainsSqlInjectionPatterns(term))
        {
            _logger.LogWarning("Potential SQL injection in search by user {UserId}: {Term}",
                userId, term);
            return BadRequest(new { Error = "Invalid search term" });
        }

        // SECURITY: Search uses parameterized query internally
        var items = await _vaultRepository.SearchByTitleAsync(userId.Value, term);

        return Ok(items.Select(MapToDto));
    }

    /// <summary>
    /// Creates a new vault item.
    /// 
    /// SECURITY: All input is validated and sanitized.
    /// </summary>
    [HttpPost]
    public async Task<ActionResult<VaultItemDto>> CreateItem([FromBody] CreateVaultItemRequest request)
    {
        var userId = GetCurrentUserId();
        if (userId == null) return Unauthorized();

        // Validate input
        var validationResult = await _createValidator.ValidateAsync(request);
        if (!validationResult.IsValid)
        {
            return BadRequest(new { Errors = validationResult.Errors.Select(e => e.ErrorMessage) });
        }

        // SECURITY: Check for XSS patterns
        if (_inputSanitizer.ContainsXssPatterns(request.Title) ||
            _inputSanitizer.ContainsXssPatterns(request.Content) ||
            _inputSanitizer.ContainsXssPatterns(request.Category))
        {
            _logger.LogWarning("Potential XSS attempt by user {UserId}", userId);
            return BadRequest(new { Error = "Invalid content detected" });
        }

        // Create vault item - content will be sanitized in repository
        var item = new VaultItem
        {
            Title = request.Title,
            Content = request.Content,
            Category = request.Category,
            UserId = userId.Value
        };

        // SECURITY: Content is sanitized before storage in CreateAsync
        var created = await _vaultRepository.CreateAsync(item);

        _logger.LogInformation("User {UserId} created vault item {ItemId}", userId, created.Id);

        return CreatedAtAction(nameof(GetItem), new { id = created.Id }, MapToDto(created));
    }

    /// <summary>
    /// Updates an existing vault item.
    /// Users can only update their own items.
    /// </summary>
    [HttpPut("{id:int}")]
    public async Task<ActionResult<VaultItemDto>> UpdateItem(int id, [FromBody] UpdateVaultItemRequest request)
    {
        var userId = GetCurrentUserId();
        if (userId == null) return Unauthorized();

        // Validate input
        var validationResult = await _updateValidator.ValidateAsync(request);
        if (!validationResult.IsValid)
        {
            return BadRequest(new { Errors = validationResult.Errors.Select(e => e.ErrorMessage) });
        }

        // Check if item exists and belongs to user
        var existingItem = await _vaultRepository.GetByIdAsync(id);
        if (existingItem == null)
        {
            return NotFound();
        }

        // SECURITY: Authorization check
        if (existingItem.UserId != userId && !IsAdmin())
        {
            _logger.LogWarning("User {UserId} attempted to update item {ItemId} owned by {OwnerId}",
                userId, id, existingItem.UserId);
            return Forbid();
        }

        // SECURITY: Check for XSS patterns
        if (_inputSanitizer.ContainsXssPatterns(request.Title) ||
            _inputSanitizer.ContainsXssPatterns(request.Content) ||
            _inputSanitizer.ContainsXssPatterns(request.Category))
        {
            _logger.LogWarning("Potential XSS attempt in update by user {UserId}", userId);
            return BadRequest(new { Error = "Invalid content detected" });
        }

        // Update the item
        existingItem.Title = request.Title;
        existingItem.Content = request.Content;
        existingItem.Category = request.Category;

        // SECURITY: Content is sanitized before storage
        var updated = await _vaultRepository.UpdateAsync(existingItem);

        _logger.LogInformation("User {UserId} updated vault item {ItemId}", userId, id);

        return Ok(MapToDto(updated));
    }

    /// <summary>
    /// Deletes a vault item.
    /// Users can only delete their own items.
    /// </summary>
    [HttpDelete("{id:int}")]
    public async Task<ActionResult> DeleteItem(int id)
    {
        var userId = GetCurrentUserId();
        if (userId == null) return Unauthorized();

        var item = await _vaultRepository.GetByIdAsync(id);
        if (item == null)
        {
            return NotFound();
        }

        // SECURITY: Authorization check
        if (item.UserId != userId && !IsAdmin())
        {
            _logger.LogWarning("User {UserId} attempted to delete item {ItemId} owned by {OwnerId}",
                userId, id, item.UserId);
            return Forbid();
        }

        await _vaultRepository.DeleteAsync(id);

        _logger.LogInformation("User {UserId} deleted vault item {ItemId}", userId, id);

        return NoContent();
    }

    /// <summary>
    /// Admin endpoint: Gets all vault items in the system.
    /// Requires Admin role.
    /// </summary>
    [HttpGet("admin/all")]
    [Authorize(Roles = Roles.Admin)]
    public async Task<ActionResult<IEnumerable<VaultItemDto>>> GetAllItems()
    {
        // This is an admin-only endpoint
        _logger.LogInformation("Admin accessed all vault items");
        
        // For demo purposes, we'll get items for user 0 (all items)
        // In a real implementation, you'd have a method to get all items
        return Ok(new List<VaultItemDto>());
    }

    #region Private Helpers

    private int? GetCurrentUserId()
    {
        var userIdClaim = User.FindFirst("userId")?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !int.TryParse(userIdClaim, out var userId))
        {
            return null;
        }
        return userId;
    }

    private bool IsAdmin()
    {
        return User.IsInRole(Roles.Admin);
    }

    private static VaultItemDto MapToDto(VaultItem item)
    {
        return new VaultItemDto
        {
            Id = item.Id,
            Title = item.Title,
            Content = item.Content,
            Category = item.Category
        };
    }

    #endregion
}
