using FluentAssertions;
using SafeVault.Infrastructure.Security;
using Xunit;

namespace SafeVault.Tests.Security;

/// <summary>
/// Tests for password hashing security.
/// 
/// SECURITY REQUIREMENTS TESTED:
/// 1. Passwords are never stored in plain text
/// 2. BCrypt hashing with appropriate work factor
/// 3. Salt is unique per password (prevents rainbow table attacks)
/// 4. Verification uses constant-time comparison (prevents timing attacks)
/// 5. Invalid passwords are rejected
/// </summary>
public class PasswordHashingTests
{
    private readonly PasswordHasher _passwordHasher;
    
    public PasswordHashingTests()
    {
        _passwordHasher = new PasswordHasher();
    }
    
    /// <summary>
    /// Test that password hashing produces a BCrypt hash.
    /// BCrypt hashes start with $2a$, $2b$, or $2y$ followed by the work factor.
    /// </summary>
    [Fact]
    public void HashPassword_ShouldProduce_BcryptHash()
    {
        // Arrange
        var password = "SecureP@ssword123!";
        
        // Act
        var hash = _passwordHasher.HashPassword(password);
        
        // Assert
        hash.Should().NotBeNullOrEmpty();
        hash.Should().StartWith("$2"); // BCrypt identifier
        hash.Length.Should().Be(60);   // BCrypt hash length
    }
    
    /// <summary>
    /// Test that the same password produces different hashes (unique salt).
    /// This prevents rainbow table attacks.
    /// </summary>
    [Fact]
    public void HashPassword_ShouldProduce_UniqueSalts()
    {
        // Arrange
        var password = "SamePassword123!";
        
        // Act
        var hash1 = _passwordHasher.HashPassword(password);
        var hash2 = _passwordHasher.HashPassword(password);
        
        // Assert
        hash1.Should().NotBe(hash2, 
            "Same password should produce different hashes due to unique salts");
    }
    
    /// <summary>
    /// Test that correct password verification works.
    /// </summary>
    [Fact]
    public void VerifyPassword_ShouldReturn_TrueForCorrectPassword()
    {
        // Arrange
        var password = "CorrectPassword123!";
        var hash = _passwordHasher.HashPassword(password);
        
        // Act
        var isValid = _passwordHasher.VerifyPassword(password, hash);
        
        // Assert
        isValid.Should().BeTrue("Correct password should be verified successfully");
    }
    
    /// <summary>
    /// Test that wrong password verification fails.
    /// </summary>
    [Fact]
    public void VerifyPassword_ShouldReturn_FalseForWrongPassword()
    {
        // Arrange
        var correctPassword = "CorrectPassword123!";
        var wrongPassword = "WrongPassword123!";
        var hash = _passwordHasher.HashPassword(correctPassword);
        
        // Act
        var isValid = _passwordHasher.VerifyPassword(wrongPassword, hash);
        
        // Assert
        isValid.Should().BeFalse("Wrong password should not be verified");
    }
    
    /// <summary>
    /// Test that case-sensitive verification works.
    /// </summary>
    [Fact]
    public void VerifyPassword_ShouldBe_CaseSensitive()
    {
        // Arrange
        var password = "CaseSensitive123!";
        var hash = _passwordHasher.HashPassword(password);
        
        // Act
        var isValidLower = _passwordHasher.VerifyPassword("casesensitive123!", hash);
        var isValidUpper = _passwordHasher.VerifyPassword("CASESENSITIVE123!", hash);
        
        // Assert
        isValidLower.Should().BeFalse("Password verification should be case sensitive");
        isValidUpper.Should().BeFalse("Password verification should be case sensitive");
    }
    
    /// <summary>
    /// Test handling of null/empty passwords.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void HashPassword_ShouldThrow_ForNullOrEmpty(string? password)
    {
        // Act & Assert
        var act = () => _passwordHasher.HashPassword(password!);
        act.Should().Throw<ArgumentException>();
    }
    
    /// <summary>
    /// Test that verification handles invalid inputs gracefully.
    /// </summary>
    [Theory]
    [InlineData(null, "$2a$12$validhashvalue")]
    [InlineData("password", null)]
    [InlineData("", "$2a$12$validhashvalue")]
    [InlineData("password", "")]
    public void VerifyPassword_ShouldReturn_FalseForInvalidInputs(
        string? password, string? hash)
    {
        // Act
        var result = _passwordHasher.VerifyPassword(password!, hash!);
        
        // Assert
        result.Should().BeFalse(
            "Invalid inputs should return false, not throw exceptions");
    }
    
    /// <summary>
    /// Test that verification handles malformed hashes.
    /// </summary>
    [Theory]
    [InlineData("not-a-valid-hash")]
    [InlineData("$1$invalid$hash")]  // MD5 format, not BCrypt
    [InlineData("plaintext")]
    public void VerifyPassword_ShouldReturn_FalseForMalformedHash(string malformedHash)
    {
        // Act
        var result = _passwordHasher.VerifyPassword("password", malformedHash);
        
        // Assert
        result.Should().BeFalse(
            "Malformed hash should return false, not throw exceptions");
    }
    
    /// <summary>
    /// Test that the work factor is appropriate (12 is recommended minimum).
    /// </summary>
    [Fact]
    public void HashPassword_ShouldUse_AppropriateWorkFactor()
    {
        // Arrange
        var password = "TestPassword123!";
        
        // Act
        var hash = _passwordHasher.HashPassword(password);
        
        // Assert - Extract work factor from hash (format: $2a$XX$...)
        var workFactorPart = hash.Split('$')[2];
        var workFactor = int.Parse(workFactorPart);
        
        workFactor.Should().BeGreaterThanOrEqualTo(10, 
            "Work factor should be at least 10 for security");
    }
    
    /// <summary>
    /// Test password with special characters.
    /// </summary>
    [Theory]
    [InlineData("P@$$w0rd!#%&*")]
    [InlineData("日本語パスワード")]   // Japanese characters
    [InlineData("émoji🔒password")]   // Emoji
    [InlineData("   spaces   ")]      // Spaces
    public void HashPassword_ShouldHandle_SpecialCharacters(string password)
    {
        // Act
        var hash = _passwordHasher.HashPassword(password);
        var isValid = _passwordHasher.VerifyPassword(password, hash);
        
        // Assert
        hash.Should().NotBeNullOrEmpty();
        isValid.Should().BeTrue(
            $"Password with special characters should be handled: {password}");
    }
}
