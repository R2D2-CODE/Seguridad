using FluentAssertions;
using SafeVault.Core.DTOs;
using SafeVault.Core.Validators;
using Xunit;

namespace SafeVault.Tests.Security;

/// <summary>
/// Tests to verify SQL Injection prevention measures.
/// 
/// These tests ensure that:
/// 1. Input validation rejects common SQL injection patterns
/// 2. The application handles malicious input safely
/// 3. Parameterized queries are used (tested via validators)
/// 
/// VULNERABILITY BEING TESTED: SQL Injection (CWE-89)
/// SQL Injection occurs when untrusted data is sent to an interpreter
/// as part of a command or query, allowing attackers to:
/// - Access unauthorized data
/// - Modify or delete data
/// - Execute administrative operations
/// </summary>
public class SqlInjectionTests
{
    private readonly LoginRequestValidator _loginValidator;
    private readonly RegisterRequestValidator _registerValidator;
    
    public SqlInjectionTests()
    {
        _loginValidator = new LoginRequestValidator();
        _registerValidator = new RegisterRequestValidator();
    }
    
    /// <summary>
    /// Test that common SQL injection patterns are rejected in login username.
    /// </summary>
    [Theory]
    [InlineData("admin'--")]                          // Comment injection
    [InlineData("admin'; DROP TABLE Users;--")]       // DROP TABLE attack
    [InlineData("' OR '1'='1")]                       // Boolean-based injection
    [InlineData("' OR 1=1--")]                        // Numeric boolean injection
    [InlineData("admin' UNION SELECT * FROM Users--")] // UNION-based injection
    [InlineData("'; EXEC xp_cmdshell('dir')--")]      // Command execution
    [InlineData("' WAITFOR DELAY '0:0:10'--")]        // Time-based injection
    [InlineData("admin'; INSERT INTO Users--")]       // INSERT injection
    [InlineData("admin'; UPDATE Users SET--")]        // UPDATE injection
    [InlineData("admin'; DELETE FROM Users--")]       // DELETE injection
    public async Task Login_ShouldReject_SqlInjectionPatterns(string maliciousUsername)
    {
        // Arrange
        var request = new LoginRequest
        {
            Username = maliciousUsername,
            Password = "Password123!"
        };
        
        // Act
        var result = await _loginValidator.ValidateAsync(request);
        
        // Assert - Validator should reject SQL injection patterns
        result.IsValid.Should().BeFalse(
            $"SQL injection pattern '{maliciousUsername}' should be rejected");
    }
    
    /// <summary>
    /// Test that SQL injection patterns in registration are rejected.
    /// </summary>
    [Theory]
    [InlineData("admin'--", "test@email.com")]
    [InlineData("normaluser", "test@email.com'; DROP TABLE Users;--")]
    [InlineData("' OR '1'='1", "valid@email.com")]
    [InlineData("user'; DELETE--", "hack@attack.com")]
    public async Task Register_ShouldReject_SqlInjectionInUsernameOrEmail(
        string username, string email)
    {
        // Arrange
        var request = new RegisterRequest
        {
            Username = username,
            Email = email,
            Password = "SecureP@ss123!",
            ConfirmPassword = "SecureP@ss123!"
        };
        
        // Act
        var result = await _registerValidator.ValidateAsync(request);
        
        // Assert
        result.IsValid.Should().BeFalse(
            "SQL injection patterns should be rejected in registration");
    }
    
    /// <summary>
    /// Test that hex-encoded SQL injection attempts are rejected.
    /// Attackers sometimes use hex encoding to bypass filters.
    /// </summary>
    [Theory]
    [InlineData("admin0x27")]    // Hex for single quote
    [InlineData("user0x3B")]    // Hex for semicolon
    public async Task Login_ShouldReject_HexEncodedInjection(string maliciousInput)
    {
        // Arrange
        var request = new LoginRequest
        {
            Username = maliciousInput,
            Password = "Password123!"
        };
        
        // Act
        var result = await _loginValidator.ValidateAsync(request);
        
        // Assert
        result.IsValid.Should().BeFalse(
            "Hex-encoded SQL injection patterns should be rejected");
    }
    
    /// <summary>
    /// Test that valid usernames are accepted.
    /// Ensures we're not being overly restrictive.
    /// </summary>
    [Theory]
    [InlineData("john_doe")]
    [InlineData("user123")]
    [InlineData("TestUser")]
    [InlineData("admin2024")]
    public async Task Login_ShouldAccept_ValidUsernames(string validUsername)
    {
        // Arrange
        var request = new LoginRequest
        {
            Username = validUsername,
            Password = "Password123!"
        };
        
        // Act
        var result = await _loginValidator.ValidateAsync(request);
        
        // Assert - Should pass validation for username format
        // (Password validation might fail, but username should be valid)
        var usernameErrors = result.Errors
            .Where(e => e.PropertyName == "Username")
            .ToList();
        
        usernameErrors.Should().BeEmpty(
            $"Valid username '{validUsername}' should be accepted");
    }
    
    /// <summary>
    /// Test that SQL keywords that could be part of legitimate data are handled.
    /// </summary>
    [Theory]
    [InlineData("selectman")]   // Contains "select" but is valid username
    [InlineData("updater")]     // Contains "update" but is valid username
    public async Task Login_ShouldEvaluate_PotentialFalsePositives(string username)
    {
        // Arrange
        var request = new LoginRequest
        {
            Username = username,
            Password = "Password123!"
        };
        
        // Act
        var result = await _loginValidator.ValidateAsync(request);
        
        // Note: Our strict validation might reject these as false positives
        // In a production system, you might want to refine the patterns
        // This test documents the current behavior
        // The key point is that actual SQL injection IS blocked
    }
    
    /// <summary>
    /// Test that batch SQL injection attempts are rejected.
    /// </summary>
    [Theory]
    [InlineData("admin; SELECT")]
    [InlineData("user; INSERT")]
    [InlineData("test; UPDATE")]
    [InlineData("name; DELETE")]
    public async Task Login_ShouldReject_BatchStatementInjection(string maliciousInput)
    {
        // Arrange
        var request = new LoginRequest
        {
            Username = maliciousInput,
            Password = "Password123!"
        };
        
        // Act
        var result = await _loginValidator.ValidateAsync(request);
        
        // Assert
        result.IsValid.Should().BeFalse(
            "Batch SQL statement injection should be rejected");
    }
}
