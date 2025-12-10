using System.Text.RegularExpressions;
using Ganss.Xss;
using SafeVault.Core.Interfaces;

namespace SafeVault.Infrastructure.Security;

/// <summary>
/// Input sanitization service to prevent XSS (Cross-Site Scripting) attacks.
/// 
/// XSS attacks occur when malicious scripts are injected into web pages
/// and executed in users' browsers. This service sanitizes user input
/// to remove or neutralize potentially dangerous content.
/// 
/// SECURITY FEATURES:
/// - HTML sanitization using HtmlSanitizer library
/// - Pattern detection for common XSS vectors
/// - SQL injection pattern detection
/// - Username sanitization for safe storage
/// </summary>
public partial class InputSanitizer : IInputSanitizer
{
    private readonly HtmlSanitizer _htmlSanitizer;
    
    // Common SQL injection patterns
    private static readonly string[] SqlInjectionPatterns = 
    [
        "--", ";--", ";", "/*", "*/", "@@",
        "char(", "nchar(", "varchar(", "nvarchar(",
        "alter", "begin", "cast", "create", "cursor",
        "declare", "delete", "drop", "end", "exec",
        "execute", "fetch", "insert", "kill", "select",
        "sys", "sysobjects", "syscolumns", "table", "update",
        "union", "where", "xp_", "sp_", "0x", "waitfor",
        "having", "or 1=1", "or '1'='1", "' or '", "1=1"
    ];
    
    // Common XSS attack patterns
    private static readonly string[] XssPatterns = 
    [
        "<script", "</script>", "javascript:", "vbscript:",
        "onload=", "onerror=", "onclick=", "onmouseover=",
        "onmouseout=", "onkeydown=", "onkeyup=", "onfocus=",
        "<iframe", "<object", "<embed", "<link", "<style",
        "expression(", "eval(", "alert(", "prompt(", "confirm(",
        "document.cookie", "document.write", "document.location",
        "window.location", "innerHTML", "outerHTML",
        "fromCharCode", "String.fromCharCode"
    ];
    
    public InputSanitizer()
    {
        // Configure HtmlSanitizer with strict settings
        _htmlSanitizer = new HtmlSanitizer();
        
        // Remove all potentially dangerous tags
        _htmlSanitizer.AllowedTags.Clear();
        
        // Only allow basic safe tags for formatting
        _htmlSanitizer.AllowedTags.Add("p");
        _htmlSanitizer.AllowedTags.Add("br");
        _htmlSanitizer.AllowedTags.Add("b");
        _htmlSanitizer.AllowedTags.Add("i");
        _htmlSanitizer.AllowedTags.Add("u");
        _htmlSanitizer.AllowedTags.Add("strong");
        _htmlSanitizer.AllowedTags.Add("em");
        
        // Clear all attributes (removes event handlers like onclick, onload, etc.)
        _htmlSanitizer.AllowedAttributes.Clear();
        
        // Remove dangerous CSS properties
        _htmlSanitizer.AllowedCssProperties.Clear();
        
        // Remove all URI schemes except safe ones
        _htmlSanitizer.AllowedSchemes.Clear();
        _htmlSanitizer.AllowedSchemes.Add("https");
        _htmlSanitizer.AllowedSchemes.Add("http");
    }
    
    /// <summary>
    /// Sanitizes HTML content to prevent XSS attacks.
    /// Removes all dangerous tags, attributes, and scripts.
    /// </summary>
    public string SanitizeHtml(string? input)
    {
        if (string.IsNullOrEmpty(input))
            return string.Empty;
        
        // Use HtmlSanitizer to remove dangerous content
        return _htmlSanitizer.Sanitize(input);
    }
    
    /// <summary>
    /// Sanitizes plain text by HTML encoding dangerous characters.
    /// Use this for content that should not contain any HTML.
    /// </summary>
    public string SanitizePlainText(string? input)
    {
        if (string.IsNullOrEmpty(input))
            return string.Empty;
        
        // HTML encode to neutralize any HTML/script content
        return System.Net.WebUtility.HtmlEncode(input);
    }
    
    /// <summary>
    /// Sanitizes a username to only allow safe characters.
    /// Only alphanumeric characters and underscores are allowed.
    /// </summary>
    public string? SanitizeUsername(string? username)
    {
        if (string.IsNullOrEmpty(username))
            return null;
        
        // Remove any character that isn't alphanumeric or underscore
        var sanitized = UsernameRegex().Replace(username, "");
        
        // Return null if the result is empty or too short
        return sanitized.Length >= 3 ? sanitized : null;
    }
    
    /// <summary>
    /// Checks if input contains SQL injection patterns.
    /// This is a defense-in-depth measure; parameterized queries are the primary defense.
    /// </summary>
    public bool ContainsSqlInjectionPatterns(string? input)
    {
        if (string.IsNullOrEmpty(input))
            return false;
        
        var lowerInput = input.ToLowerInvariant();
        return SqlInjectionPatterns.Any(pattern => lowerInput.Contains(pattern));
    }
    
    /// <summary>
    /// Checks if input contains XSS patterns.
    /// This is a defense-in-depth measure; output encoding is the primary defense.
    /// </summary>
    public bool ContainsXssPatterns(string? input)
    {
        if (string.IsNullOrEmpty(input))
            return false;
        
        var lowerInput = input.ToLowerInvariant();
        return XssPatterns.Any(pattern => lowerInput.Contains(pattern));
    }
    
    // Regex for username validation - only alphanumeric and underscore
    [GeneratedRegex(@"[^a-zA-Z0-9_]")]
    private static partial Regex UsernameRegex();
}
