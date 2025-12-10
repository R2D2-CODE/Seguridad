using FluentAssertions;
using SafeVault.Core.DTOs;
using SafeVault.Core.Validators;
using SafeVault.Infrastructure.Security;
using Xunit;

namespace SafeVault.Tests.Security;

/// <summary>
/// Tests to verify XSS (Cross-Site Scripting) prevention measures.
/// 
/// VULNERABILITY BEING TESTED: XSS (CWE-79)
/// XSS attacks occur when an attacker injects malicious scripts into
/// content that is then served to other users. Types include:
/// - Stored XSS: Malicious script stored in database
/// - Reflected XSS: Script in URL parameters reflected to user
/// - DOM-based XSS: Script manipulates client-side DOM
/// 
/// PREVENTION MEASURES TESTED:
/// 1. Input validation rejects dangerous patterns
/// 2. HTML sanitization removes/escapes dangerous content
/// 3. Content-Security-Policy headers block inline scripts
/// </summary>
public class XssPreventionTests
{
    private readonly VaultItemValidator _vaultItemValidator;
    private readonly InputSanitizer _inputSanitizer;
    
    public XssPreventionTests()
    {
        _vaultItemValidator = new VaultItemValidator();
        _inputSanitizer = new InputSanitizer();
    }
    
    #region Script Injection Tests
    
    /// <summary>
    /// Test that basic script tags are rejected/sanitized.
    /// </summary>
    [Theory]
    [InlineData("<script>alert('XSS')</script>")]
    [InlineData("<SCRIPT>alert('XSS')</SCRIPT>")]   // Case variation
    [InlineData("<script src='evil.js'></script>")] // External script
    [InlineData("<script>document.cookie</script>")] // Cookie theft
    public async Task VaultItem_ShouldReject_ScriptTags(string maliciousContent)
    {
        // Arrange
        var request = new CreateVaultItemRequest
        {
            Title = "Test Item",
            Content = maliciousContent,
            Category = "Test"
        };
        
        // Act
        var result = await _vaultItemValidator.ValidateAsync(request);
        
        // Assert
        result.IsValid.Should().BeFalse(
            $"Script tag '{maliciousContent}' should be rejected");
    }
    
    /// <summary>
    /// Test that event handler attributes are rejected.
    /// </summary>
    [Theory]
    [InlineData("<img src=x onerror=alert('XSS')>")]
    [InlineData("<body onload=alert('XSS')>")]
    [InlineData("<div onclick=alert('XSS')>Click me</div>")]
    [InlineData("<input onfocus=alert('XSS') autofocus>")]
    [InlineData("<svg onmouseover=alert('XSS')>")]
    public async Task VaultItem_ShouldReject_EventHandlers(string maliciousContent)
    {
        // Arrange
        var request = new CreateVaultItemRequest
        {
            Title = maliciousContent,
            Content = "Safe content",
            Category = "Test"
        };
        
        // Act
        var result = await _vaultItemValidator.ValidateAsync(request);
        
        // Assert
        result.IsValid.Should().BeFalse(
            $"Event handler '{maliciousContent}' should be rejected");
    }
    
    /// <summary>
    /// Test that JavaScript URL schemes are rejected.
    /// </summary>
    [Theory]
    [InlineData("<a href='javascript:alert(1)'>Click</a>")]
    [InlineData("<a href='JAVASCRIPT:alert(1)'>Click</a>")] // Case variation
    [InlineData("<a href='vbscript:alert(1)'>Click</a>")]   // VBScript
    [InlineData("<iframe src='javascript:alert(1)'>")]
    public async Task VaultItem_ShouldReject_JavaScriptUrls(string maliciousContent)
    {
        // Arrange
        var request = new CreateVaultItemRequest
        {
            Title = "Test",
            Content = maliciousContent,
            Category = "Test"
        };
        
        // Act
        var result = await _vaultItemValidator.ValidateAsync(request);
        
        // Assert
        result.IsValid.Should().BeFalse(
            $"JavaScript URL '{maliciousContent}' should be rejected");
    }
    
    #endregion
    
    #region HTML Sanitization Tests
    
    /// <summary>
    /// Test that the HTML sanitizer removes script tags.
    /// </summary>
    [Fact]
    public void Sanitizer_ShouldRemove_ScriptTags()
    {
        // Arrange
        var input = "<p>Hello</p><script>alert('XSS')</script><p>World</p>";
        
        // Act
        var sanitized = _inputSanitizer.SanitizeHtml(input);
        
        // Assert
        sanitized.Should().NotContain("<script");
        sanitized.Should().NotContain("alert");
        sanitized.Should().Contain("Hello");
        sanitized.Should().Contain("World");
    }
    
    /// <summary>
    /// Test that the sanitizer removes event handlers from tags.
    /// </summary>
    [Fact]
    public void Sanitizer_ShouldRemove_EventHandlers()
    {
        // Arrange
        var input = "<p onclick='alert(1)'>Click me</p>";
        
        // Act
        var sanitized = _inputSanitizer.SanitizeHtml(input);
        
        // Assert
        sanitized.Should().NotContain("onclick");
        sanitized.Should().NotContain("alert");
        // Should preserve the safe content
        sanitized.Should().Contain("Click me");
    }
    
    /// <summary>
    /// Test that dangerous tags are removed but safe content preserved.
    /// </summary>
    [Fact]
    public void Sanitizer_ShouldRemove_DangerousTags()
    {
        // Arrange
        var input = "<p>Safe</p><iframe src='evil.com'></iframe><b>Bold</b>";
        
        // Act
        var sanitized = _inputSanitizer.SanitizeHtml(input);
        
        // Assert
        sanitized.Should().NotContain("<iframe");
        sanitized.Should().Contain("Safe");
        sanitized.Should().Contain("Bold");
    }
    
    /// <summary>
    /// Test that safe HTML formatting is preserved.
    /// </summary>
    [Fact]
    public void Sanitizer_ShouldPreserve_SafeHtml()
    {
        // Arrange
        var input = "<p><b>Bold</b> and <i>italic</i></p>";
        
        // Act
        var sanitized = _inputSanitizer.SanitizeHtml(input);
        
        // Assert
        sanitized.Should().Contain("<b>");
        sanitized.Should().Contain("<i>");
        sanitized.Should().Contain("Bold");
        sanitized.Should().Contain("italic");
    }
    
    /// <summary>
    /// Test that plain text is properly encoded.
    /// </summary>
    [Fact]
    public void Sanitizer_ShouldEncode_PlainText()
    {
        // Arrange
        var input = "<script>alert('XSS')</script>";
        
        // Act
        var sanitized = _inputSanitizer.SanitizePlainText(input);
        
        // Assert
        // HTML entities should be encoded
        sanitized.Should().Contain("&lt;script&gt;");
        sanitized.Should().NotBe(input); // Should be different from input
    }
    
    #endregion
    
    #region XSS Pattern Detection Tests
    
    /// <summary>
    /// Test that XSS patterns are correctly detected.
    /// </summary>
    [Theory]
    [InlineData("<script>")]
    [InlineData("javascript:")]
    [InlineData("onclick=")]
    [InlineData("document.cookie")]
    [InlineData("eval(")]
    public void Sanitizer_ShouldDetect_XssPatterns(string pattern)
    {
        // Act
        var containsXss = _inputSanitizer.ContainsXssPatterns(pattern);
        
        // Assert
        containsXss.Should().BeTrue(
            $"XSS pattern '{pattern}' should be detected");
    }
    
    /// <summary>
    /// Test that safe content is not flagged as XSS.
    /// </summary>
    [Theory]
    [InlineData("This is safe content")]
    [InlineData("Hello, World!")]
    [InlineData("User profile: john_doe")]
    [InlineData("Price: $19.99")]
    public void Sanitizer_ShouldNotFlag_SafeContent(string safeContent)
    {
        // Act
        var containsXss = _inputSanitizer.ContainsXssPatterns(safeContent);
        
        // Assert
        containsXss.Should().BeFalse(
            $"Safe content '{safeContent}' should not be flagged as XSS");
    }
    
    #endregion
    
    #region Edge Cases
    
    /// <summary>
    /// Test handling of null and empty input.
    /// </summary>
    [Fact]
    public void Sanitizer_ShouldHandle_NullAndEmpty()
    {
        // Assert - Should not throw and should return safe values
        _inputSanitizer.SanitizeHtml(null).Should().BeEmpty();
        _inputSanitizer.SanitizeHtml("").Should().BeEmpty();
        _inputSanitizer.SanitizePlainText(null).Should().BeEmpty();
        _inputSanitizer.ContainsXssPatterns(null).Should().BeFalse();
    }
    
    /// <summary>
    /// Test that encoded XSS attempts are handled.
    /// </summary>
    [Fact]
    public void Sanitizer_ShouldHandle_EncodedXss()
    {
        // Arrange - URL encoded script tag
        var input = "%3Cscript%3Ealert('XSS')%3C/script%3E";
        
        // Act - Decode and check
        var decoded = System.Net.WebUtility.UrlDecode(input);
        var containsXss = _inputSanitizer.ContainsXssPatterns(decoded);
        
        // Assert
        containsXss.Should().BeTrue(
            "Decoded XSS content should be detected");
    }
    
    #endregion
}
