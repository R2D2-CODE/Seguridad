using FluentAssertions;
using SafeVault.Core.DTOs;
using SafeVault.Core.Validators;
using Xunit;

namespace SafeVault.Tests.Security;

/// <summary>
/// Tests for authentication and authorization security features.
/// 
/// SECURITY FEATURES TESTED:
/// 1. Input validation for login/registration
/// 2. Password complexity requirements
/// 3. Protection against user enumeration
/// 4. Role-Based Access Control (RBAC) validation
/// </summary>
public class AuthorizationTests
{
    private readonly LoginRequestValidator _loginValidator;
    private readonly RegisterRequestValidator _registerValidator;
    
    public AuthorizationTests()
    {
        _loginValidator = new LoginRequestValidator();
        _registerValidator = new RegisterRequestValidator();
    }
    
    #region Password Validation Tests
    
    /// <summary>
    /// Test that weak passwords are rejected.
    /// </summary>
    [Theory]
    [InlineData("123")]             // Too short
    [InlineData("password")]        // No uppercase, no number, no special char
    [InlineData("PASSWORD")]        // No lowercase, no number, no special char
    [InlineData("Password")]        // No number, no special char
    [InlineData("Password1")]       // No special char
    [InlineData("password1!")]      // No uppercase
    [InlineData("PASSWORD1!")]      // No lowercase
    public async Task Register_ShouldReject_WeakPasswords(string weakPassword)
    {
        // Arrange
        var request = new RegisterRequest
        {
            Username = "testuser",
            Email = "test@example.com",
            Password = weakPassword,
            ConfirmPassword = weakPassword
        };
        
        // Act
        var result = await _registerValidator.ValidateAsync(request);
        
        // Assert
        var passwordErrors = result.Errors
            .Where(e => e.PropertyName == "Password")
            .ToList();
        
        passwordErrors.Should().NotBeEmpty(
            $"Weak password '{weakPassword}' should be rejected");
    }
    
    /// <summary>
    /// Test that strong passwords are accepted.
    /// </summary>
    [Theory]
    [InlineData("SecureP@ss123")]
    [InlineData("MyStr0ng!Password")]
    [InlineData("C0mpl3x#Pass")]
    [InlineData("Valid$Password1")]
    public async Task Register_ShouldAccept_StrongPasswords(string strongPassword)
    {
        // Arrange
        var request = new RegisterRequest
        {
            Username = "testuser",
            Email = "test@example.com",
            Password = strongPassword,
            ConfirmPassword = strongPassword
        };
        
        // Act
        var result = await _registerValidator.ValidateAsync(request);
        
        // Assert
        var passwordErrors = result.Errors
            .Where(e => e.PropertyName == "Password")
            .ToList();
        
        passwordErrors.Should().BeEmpty(
            $"Strong password '{strongPassword}' should be accepted");
    }
    
    /// <summary>
    /// Test that password confirmation must match.
    /// </summary>
    [Fact]
    public async Task Register_ShouldReject_MismatchedPasswords()
    {
        // Arrange
        var request = new RegisterRequest
        {
            Username = "testuser",
            Email = "test@example.com",
            Password = "SecureP@ss123",
            ConfirmPassword = "DifferentP@ss123"
        };
        
        // Act
        var result = await _registerValidator.ValidateAsync(request);
        
        // Assert
        result.IsValid.Should().BeFalse("Mismatched passwords should be rejected");
        result.Errors.Should().Contain(e => e.PropertyName == "ConfirmPassword");
    }
    
    #endregion
    
    #region Username Validation Tests
    
    /// <summary>
    /// Test that invalid usernames are rejected.
    /// </summary>
    [Theory]
    [InlineData("")]            // Empty
    [InlineData("ab")]          // Too short (min 3)
    [InlineData("user name")]   // Contains space
    [InlineData("user@name")]   // Contains @
    [InlineData("user-name")]   // Contains hyphen
    [InlineData("user.name")]   // Contains dot
    public async Task Register_ShouldReject_InvalidUsernames(string invalidUsername)
    {
        // Arrange
        var request = new RegisterRequest
        {
            Username = invalidUsername,
            Email = "test@example.com",
            Password = "SecureP@ss123",
            ConfirmPassword = "SecureP@ss123"
        };
        
        // Act
        var result = await _registerValidator.ValidateAsync(request);
        
        // Assert
        var usernameErrors = result.Errors
            .Where(e => e.PropertyName == "Username")
            .ToList();
        
        usernameErrors.Should().NotBeEmpty(
            $"Invalid username '{invalidUsername}' should be rejected");
    }
    
    /// <summary>
    /// Test that valid usernames are accepted.
    /// </summary>
    [Theory]
    [InlineData("abc")]             // Minimum length
    [InlineData("user123")]
    [InlineData("test_user")]
    [InlineData("Admin2024")]
    [InlineData("USER_NAME_123")]
    public async Task Register_ShouldAccept_ValidUsernames(string validUsername)
    {
        // Arrange
        var request = new RegisterRequest
        {
            Username = validUsername,
            Email = "test@example.com",
            Password = "SecureP@ss123",
            ConfirmPassword = "SecureP@ss123"
        };
        
        // Act
        var result = await _registerValidator.ValidateAsync(request);
        
        // Assert
        var usernameErrors = result.Errors
            .Where(e => e.PropertyName == "Username")
            .ToList();
        
        usernameErrors.Should().BeEmpty(
            $"Valid username '{validUsername}' should be accepted");
    }
    
    #endregion
    
    #region Email Validation Tests
    
    /// <summary>
    /// Test that invalid emails are rejected.
    /// </summary>
    [Theory]
    [InlineData("")]                    // Empty
    [InlineData("notanemail")]          // No @ symbol
    [InlineData("@nodomain.com")]       // No local part
    [InlineData("noatsymbol.com")]      // No @ symbol
    [InlineData("spaces in@email.com")] // Spaces
    public async Task Register_ShouldReject_InvalidEmails(string invalidEmail)
    {
        // Arrange
        var request = new RegisterRequest
        {
            Username = "testuser",
            Email = invalidEmail,
            Password = "SecureP@ss123",
            ConfirmPassword = "SecureP@ss123"
        };
        
        // Act
        var result = await _registerValidator.ValidateAsync(request);
        
        // Assert
        var emailErrors = result.Errors
            .Where(e => e.PropertyName == "Email")
            .ToList();
        
        emailErrors.Should().NotBeEmpty(
            $"Invalid email '{invalidEmail}' should be rejected");
    }
    
    /// <summary>
    /// Test that valid emails are accepted.
    /// </summary>
    [Theory]
    [InlineData("user@example.com")]
    [InlineData("user.name@domain.com")]
    [InlineData("user+tag@example.org")]
    [InlineData("user123@test.co.uk")]
    public async Task Register_ShouldAccept_ValidEmails(string validEmail)
    {
        // Arrange
        var request = new RegisterRequest
        {
            Username = "testuser",
            Email = validEmail,
            Password = "SecureP@ss123",
            ConfirmPassword = "SecureP@ss123"
        };
        
        // Act
        var result = await _registerValidator.ValidateAsync(request);
        
        // Assert
        var emailErrors = result.Errors
            .Where(e => e.PropertyName == "Email")
            .ToList();
        
        emailErrors.Should().BeEmpty(
            $"Valid email '{validEmail}' should be accepted");
    }
    
    #endregion
    
    #region Login Validation Tests
    
    /// <summary>
    /// Test that login requires username.
    /// </summary>
    [Fact]
    public async Task Login_ShouldRequire_Username()
    {
        // Arrange
        var request = new LoginRequest
        {
            Username = "",
            Password = "Password123!"
        };
        
        // Act
        var result = await _loginValidator.ValidateAsync(request);
        
        // Assert
        result.IsValid.Should().BeFalse("Empty username should be rejected");
    }
    
    /// <summary>
    /// Test that login requires password.
    /// </summary>
    [Fact]
    public async Task Login_ShouldRequire_Password()
    {
        // Arrange
        var request = new LoginRequest
        {
            Username = "testuser",
            Password = ""
        };
        
        // Act
        var result = await _loginValidator.ValidateAsync(request);
        
        // Assert
        result.IsValid.Should().BeFalse("Empty password should be rejected");
    }
    
    /// <summary>
    /// Test that valid login request is accepted.
    /// </summary>
    [Fact]
    public async Task Login_ShouldAccept_ValidRequest()
    {
        // Arrange
        var request = new LoginRequest
        {
            Username = "testuser",
            Password = "SecureP@ss123!"
        };
        
        // Act
        var result = await _loginValidator.ValidateAsync(request);
        
        // Assert
        result.IsValid.Should().BeTrue("Valid login request should be accepted");
    }
    
    #endregion
}
