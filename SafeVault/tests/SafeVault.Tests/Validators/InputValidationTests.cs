using FluentAssertions;
using SafeVault.Core.DTOs;
using SafeVault.Core.Validators;
using Xunit;

namespace SafeVault.Tests.Validators;

/// <summary>
/// Comprehensive tests for input validation.
/// 
/// Tests ensure that all user input is properly validated
/// to prevent various types of attacks and ensure data integrity.
/// </summary>
public class InputValidationTests
{
    private readonly LoginRequestValidator _loginValidator;
    private readonly RegisterRequestValidator _registerValidator;
    private readonly VaultItemValidator _vaultItemValidator;
    private readonly UpdateVaultItemValidator _updateVaultItemValidator;
    
    public InputValidationTests()
    {
        _loginValidator = new LoginRequestValidator();
        _registerValidator = new RegisterRequestValidator();
        _vaultItemValidator = new VaultItemValidator();
        _updateVaultItemValidator = new UpdateVaultItemValidator();
    }
    
    #region Length Limit Tests
    
    /// <summary>
    /// Test that username length limits are enforced.
    /// </summary>
    [Fact]
    public async Task Username_ShouldEnforce_LengthLimits()
    {
        // Test minimum length (3 characters)
        var tooShort = new RegisterRequest
        {
            Username = "ab",
            Email = "test@example.com",
            Password = "SecureP@ss123",
            ConfirmPassword = "SecureP@ss123"
        };
        
        var shortResult = await _registerValidator.ValidateAsync(tooShort);
        shortResult.Errors.Should().Contain(e => 
            e.PropertyName == "Username" && e.ErrorMessage.Contains("3"));
        
        // Test maximum length (50 characters)
        var tooLong = new RegisterRequest
        {
            Username = new string('a', 51),
            Email = "test@example.com",
            Password = "SecureP@ss123",
            ConfirmPassword = "SecureP@ss123"
        };
        
        var longResult = await _registerValidator.ValidateAsync(tooLong);
        longResult.Errors.Should().Contain(e => 
            e.PropertyName == "Username" && e.ErrorMessage.Contains("50"));
    }
    
    /// <summary>
    /// Test that vault item title length limits are enforced.
    /// </summary>
    [Fact]
    public async Task VaultItemTitle_ShouldEnforce_LengthLimits()
    {
        // Test maximum length (200 characters)
        var tooLong = new CreateVaultItemRequest
        {
            Title = new string('x', 201),
            Content = "Valid content",
            Category = "Test"
        };
        
        var result = await _vaultItemValidator.ValidateAsync(tooLong);
        result.Errors.Should().Contain(e => 
            e.PropertyName == "Title" && e.ErrorMessage.Contains("200"));
    }
    
    /// <summary>
    /// Test that vault item content length limits are enforced.
    /// </summary>
    [Fact]
    public async Task VaultItemContent_ShouldEnforce_LengthLimits()
    {
        // Test maximum length (10000 characters)
        var tooLong = new CreateVaultItemRequest
        {
            Title = "Valid Title",
            Content = new string('x', 10001),
            Category = "Test"
        };
        
        var result = await _vaultItemValidator.ValidateAsync(tooLong);
        result.Errors.Should().Contain(e => 
            e.PropertyName == "Content" && e.ErrorMessage.Contains("10000"));
    }
    
    #endregion
    
    #region Required Field Tests
    
    /// <summary>
    /// Test that required fields are enforced on login.
    /// </summary>
    [Fact]
    public async Task Login_ShouldRequire_AllFields()
    {
        var emptyRequest = new LoginRequest
        {
            Username = "",
            Password = ""
        };
        
        var result = await _loginValidator.ValidateAsync(emptyRequest);
        
        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.PropertyName == "Username");
        result.Errors.Should().Contain(e => e.PropertyName == "Password");
    }
    
    /// <summary>
    /// Test that required fields are enforced on registration.
    /// </summary>
    [Fact]
    public async Task Register_ShouldRequire_AllFields()
    {
        var emptyRequest = new RegisterRequest
        {
            Username = "",
            Email = "",
            Password = "",
            ConfirmPassword = ""
        };
        
        var result = await _registerValidator.ValidateAsync(emptyRequest);
        
        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.PropertyName == "Username");
        result.Errors.Should().Contain(e => e.PropertyName == "Email");
        result.Errors.Should().Contain(e => e.PropertyName == "Password");
        result.Errors.Should().Contain(e => e.PropertyName == "ConfirmPassword");
    }
    
    /// <summary>
    /// Test that required fields are enforced on vault items.
    /// </summary>
    [Fact]
    public async Task VaultItem_ShouldRequire_TitleAndContent()
    {
        var emptyRequest = new CreateVaultItemRequest
        {
            Title = "",
            Content = "",
            Category = null
        };
        
        var result = await _vaultItemValidator.ValidateAsync(emptyRequest);
        
        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.PropertyName == "Title");
        result.Errors.Should().Contain(e => e.PropertyName == "Content");
        // Category is optional
        result.Errors.Should().NotContain(e => e.PropertyName == "Category");
    }
    
    #endregion
    
    #region Valid Input Tests
    
    /// <summary>
    /// Test that completely valid registration is accepted.
    /// </summary>
    [Fact]
    public async Task Register_ShouldAccept_CompletelyValidRequest()
    {
        var validRequest = new RegisterRequest
        {
            Username = "validuser",
            Email = "valid@example.com",
            Password = "SecureP@ss123!",
            ConfirmPassword = "SecureP@ss123!"
        };
        
        var result = await _registerValidator.ValidateAsync(validRequest);
        
        result.IsValid.Should().BeTrue("Completely valid request should be accepted");
    }
    
    /// <summary>
    /// Test that valid vault item creation is accepted.
    /// </summary>
    [Fact]
    public async Task VaultItem_ShouldAccept_ValidRequest()
    {
        var validRequest = new CreateVaultItemRequest
        {
            Title = "My Secret Note",
            Content = "This is secure content that should be stored safely.",
            Category = "Personal"
        };
        
        var result = await _vaultItemValidator.ValidateAsync(validRequest);
        
        result.IsValid.Should().BeTrue("Valid vault item should be accepted");
    }
    
    /// <summary>
    /// Test that vault item with optional fields empty is accepted.
    /// </summary>
    [Fact]
    public async Task VaultItem_ShouldAccept_WithoutOptionalCategory()
    {
        var request = new CreateVaultItemRequest
        {
            Title = "My Secret Note",
            Content = "This is secure content.",
            Category = null
        };
        
        var result = await _vaultItemValidator.ValidateAsync(request);
        
        result.IsValid.Should().BeTrue("Vault item without category should be accepted");
    }
    
    #endregion
    
    #region Update Validation Tests
    
    /// <summary>
    /// Test that update validator works correctly.
    /// </summary>
    [Fact]
    public async Task UpdateVaultItem_ShouldValidate_Correctly()
    {
        var validRequest = new UpdateVaultItemRequest
        {
            Title = "Updated Title",
            Content = "Updated content",
            Category = "Updated Category"
        };
        
        var result = await _updateVaultItemValidator.ValidateAsync(validRequest);
        
        result.IsValid.Should().BeTrue("Valid update request should be accepted");
    }
    
    /// <summary>
    /// Test that update validator rejects XSS.
    /// </summary>
    [Fact]
    public async Task UpdateVaultItem_ShouldReject_Xss()
    {
        var xssRequest = new UpdateVaultItemRequest
        {
            Title = "<script>alert('XSS')</script>",
            Content = "Normal content",
            Category = "Test"
        };
        
        var result = await _updateVaultItemValidator.ValidateAsync(xssRequest);
        
        result.IsValid.Should().BeFalse("XSS in update should be rejected");
    }
    
    #endregion
}
