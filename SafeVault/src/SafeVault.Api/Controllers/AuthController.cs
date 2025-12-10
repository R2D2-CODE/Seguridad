using FluentValidation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Core.DTOs;
using SafeVault.Core.Entities;
using SafeVault.Core.Interfaces;

namespace SafeVault.Api.Controllers;

/// <summary>
/// Authentication controller handling user registration and login.
/// 
/// SECURITY FEATURES IMPLEMENTED:
/// - Password hashing using BCrypt (never stores plain text passwords)
/// - Input validation using FluentValidation
/// - JWT token generation for authenticated sessions
/// - Protection against SQL injection via parameterized queries
/// - Protection against XSS via input sanitization
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IUserRepository _userRepository;
    private readonly IPasswordHasher _passwordHasher;
    private readonly IJwtTokenService _jwtTokenService;
    private readonly IInputSanitizer _inputSanitizer;
    private readonly IValidator<LoginRequest> _loginValidator;
    private readonly IValidator<RegisterRequest> _registerValidator;
    private readonly ILogger<AuthController> _logger;

    public AuthController(
        IUserRepository userRepository,
        IPasswordHasher passwordHasher,
        IJwtTokenService jwtTokenService,
        IInputSanitizer inputSanitizer,
        IValidator<LoginRequest> loginValidator,
        IValidator<RegisterRequest> registerValidator,
        ILogger<AuthController> logger)
    {
        _userRepository = userRepository;
        _passwordHasher = passwordHasher;
        _jwtTokenService = jwtTokenService;
        _inputSanitizer = inputSanitizer;
        _loginValidator = loginValidator;
        _registerValidator = registerValidator;
        _logger = logger;
    }

    /// <summary>
    /// Registers a new user account.
    /// 
    /// Security measures:
    /// - Validates all input fields
    /// - Checks for SQL injection and XSS patterns
    /// - Hashes password before storage
    /// - Sanitizes username and email
    /// </summary>
    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<ActionResult<AuthResponse>> Register([FromBody] RegisterRequest request)
    {
        // Validate input using FluentValidation
        var validationResult = await _registerValidator.ValidateAsync(request);
        if (!validationResult.IsValid)
        {
            return BadRequest(new { Errors = validationResult.Errors.Select(e => e.ErrorMessage) });
        }

        // SECURITY: Check for SQL injection patterns (defense in depth)
        if (_inputSanitizer.ContainsSqlInjectionPatterns(request.Username) ||
            _inputSanitizer.ContainsSqlInjectionPatterns(request.Email))
        {
            _logger.LogWarning("Potential SQL injection attempt detected in registration: {Username}", 
                request.Username);
            return BadRequest(new { Error = "Invalid characters detected in input" });
        }

        // SECURITY: Check for XSS patterns
        if (_inputSanitizer.ContainsXssPatterns(request.Username) ||
            _inputSanitizer.ContainsXssPatterns(request.Email))
        {
            _logger.LogWarning("Potential XSS attempt detected in registration: {Username}", 
                request.Username);
            return BadRequest(new { Error = "Invalid characters detected in input" });
        }

        // Check if username or email already exists
        if (await _userRepository.UsernameExistsAsync(request.Username))
        {
            return Conflict(new { Error = "Username already exists" });
        }

        if (await _userRepository.EmailExistsAsync(request.Email))
        {
            return Conflict(new { Error = "Email already exists" });
        }

        // SECURITY: Hash password before storage - NEVER store plain text passwords
        var passwordHash = _passwordHasher.HashPassword(request.Password);

        // Sanitize username before storage
        var sanitizedUsername = _inputSanitizer.SanitizeUsername(request.Username);
        if (string.IsNullOrEmpty(sanitizedUsername))
        {
            return BadRequest(new { Error = "Invalid username format" });
        }

        // Create new user with hashed password
        var user = new User
        {
            Username = sanitizedUsername,
            Email = request.Email.ToLowerInvariant().Trim(),
            PasswordHash = passwordHash,
            Role = Roles.User, // Default role is User
            CreatedAt = DateTime.UtcNow,
            IsActive = true
        };

        await _userRepository.CreateAsync(user);

        _logger.LogInformation("New user registered: {Username}", user.Username);

        // Generate JWT token for immediate login
        var token = _jwtTokenService.GenerateToken(user);

        return Ok(new AuthResponse
        {
            Token = token,
            ExpiresAt = _jwtTokenService.GetTokenExpiration(),
            Username = user.Username,
            Role = user.Role
        });
    }

    /// <summary>
    /// Authenticates a user and returns a JWT token.
    /// 
    /// Security measures:
    /// - Validates input
    /// - Uses constant-time password comparison
    /// - Logs failed attempts for security monitoring
    /// - Returns generic error message to prevent user enumeration
    /// </summary>
    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<ActionResult<AuthResponse>> Login([FromBody] LoginRequest request)
    {
        // Validate input
        var validationResult = await _loginValidator.ValidateAsync(request);
        if (!validationResult.IsValid)
        {
            return BadRequest(new { Errors = validationResult.Errors.Select(e => e.ErrorMessage) });
        }

        // SECURITY: Check for injection patterns
        if (_inputSanitizer.ContainsSqlInjectionPatterns(request.Username))
        {
            _logger.LogWarning("Potential SQL injection attempt in login: {Username}", request.Username);
            return Unauthorized(new { Error = "Invalid username or password" });
        }

        // Find user by username
        // SECURITY: Uses parameterized query internally
        var user = await _userRepository.GetByUsernameAsync(request.Username);

        // SECURITY: Use generic error message to prevent user enumeration
        if (user == null)
        {
            _logger.LogWarning("Login attempt for non-existent user: {Username}", request.Username);
            return Unauthorized(new { Error = "Invalid username or password" });
        }

        // Check if account is active
        if (!user.IsActive)
        {
            _logger.LogWarning("Login attempt for inactive account: {Username}", request.Username);
            return Unauthorized(new { Error = "Account is inactive" });
        }

        // SECURITY: Verify password using constant-time comparison
        if (!_passwordHasher.VerifyPassword(request.Password, user.PasswordHash))
        {
            _logger.LogWarning("Failed login attempt for user: {Username}", request.Username);
            return Unauthorized(new { Error = "Invalid username or password" });
        }

        _logger.LogInformation("User logged in successfully: {Username}", user.Username);

        // Generate JWT token
        var token = _jwtTokenService.GenerateToken(user);

        return Ok(new AuthResponse
        {
            Token = token,
            ExpiresAt = _jwtTokenService.GetTokenExpiration(),
            Username = user.Username,
            Role = user.Role
        });
    }

    /// <summary>
    /// Returns the current authenticated user's information.
    /// Requires valid JWT token.
    /// </summary>
    [HttpGet("me")]
    [Authorize]
    public async Task<ActionResult<object>> GetCurrentUser()
    {
        var userIdClaim = User.FindFirst("userId")?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !int.TryParse(userIdClaim, out var userId))
        {
            return Unauthorized();
        }

        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
        {
            return NotFound();
        }

        return Ok(new
        {
            user.Id,
            user.Username,
            user.Email,
            user.Role,
            user.CreatedAt
        });
    }
}
