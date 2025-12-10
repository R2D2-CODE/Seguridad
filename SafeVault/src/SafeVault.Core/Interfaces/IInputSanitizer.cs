namespace SafeVault.Core.Interfaces;

/// <summary>
/// Interface for input sanitization to prevent XSS attacks.
/// All user input should be sanitized before storage or display.
/// </summary>
public interface IInputSanitizer
{
    /// <summary>
    /// Sanitizes HTML content to prevent XSS attacks.
    /// Removes dangerous scripts and malicious content.
    /// </summary>
    /// <param name="input">Raw user input that may contain malicious content.</param>
    /// <returns>Sanitized safe string.</returns>
    string SanitizeHtml(string? input);
    
    /// <summary>
    /// Sanitizes plain text input by removing or escaping dangerous characters.
    /// </summary>
    /// <param name="input">Raw user input.</param>
    /// <returns>Sanitized safe string.</returns>
    string SanitizePlainText(string? input);
    
    /// <summary>
    /// Validates and sanitizes a username.
    /// Allows only alphanumeric characters and underscores.
    /// </summary>
    /// <param name="username">Raw username input.</param>
    /// <returns>Sanitized username or null if invalid.</returns>
    string? SanitizeUsername(string? username);
    
    /// <summary>
    /// Checks if input contains potential SQL injection patterns.
    /// </summary>
    /// <param name="input">Input to check.</param>
    /// <returns>True if suspicious patterns detected.</returns>
    bool ContainsSqlInjectionPatterns(string? input);
    
    /// <summary>
    /// Checks if input contains potential XSS patterns.
    /// </summary>
    /// <param name="input">Input to check.</param>
    /// <returns>True if suspicious patterns detected.</returns>
    bool ContainsXssPatterns(string? input);
}
