using FluentValidation;
using SafeVault.Core.DTOs;

namespace SafeVault.Core.Validators;

/// <summary>
/// Validator for registration requests.
/// Implements comprehensive validation for security and data integrity.
/// </summary>
public class RegisterRequestValidator : AbstractValidator<RegisterRequest>
{
    // Dangerous SQL injection patterns to detect
    private static readonly string[] SqlInjectionPatterns = 
    [
        "--", ";--", ";", "/*", "*/", "@@",
        "char(", "nchar(", "varchar(", "nvarchar(",
        "alter", "begin", "cast", "create", "cursor",
        "declare", "delete", "drop", "end", "exec",
        "execute", "fetch", "insert", "kill", "select",
        "sys", "sysobjects", "syscolumns", "table", "update",
        "union", "where", "xp_", "sp_", "0x", "waitfor"
    ];
    
    // SQL patterns that are dangerous for usernames (more restrictive)
    private static readonly string[] SqlInjectionPatternsWithAt = 
    [
        "--", ";--", ";", "/*", "*/", "@@", "@",
        "char(", "nchar(", "varchar(", "nvarchar(",
        "alter", "begin", "cast", "create", "cursor",
        "declare", "delete", "drop", "end", "exec",
        "execute", "fetch", "insert", "kill", "select",
        "sys", "sysobjects", "syscolumns", "table", "update",
        "union", "where", "xp_", "sp_", "0x", "waitfor"
    ];
    
    // Dangerous XSS patterns to detect
    private static readonly string[] XssPatterns = 
    [
        "<script", "</script", "javascript:", "vbscript:",
        "onload=", "onerror=", "onclick=", "onmouseover=",
        "<iframe", "<object", "<embed", "<link", "<style",
        "expression(", "eval(", "alert(", "document.cookie"
    ];
    
    public RegisterRequestValidator()
    {
        RuleFor(x => x.Username)
            .NotEmpty().WithMessage("Username is required")
            .MinimumLength(3).WithMessage("Username must be at least 3 characters")
            .MaximumLength(50).WithMessage("Username cannot exceed 50 characters")
            .Matches(@"^[a-zA-Z0-9_]+$").WithMessage("Username can only contain letters, numbers, and underscores")
            .Must(NotContainSqlInjectionWithAt).WithMessage("Username contains invalid characters")
            .Must(NotContainXss).WithMessage("Username contains invalid characters");
        
        RuleFor(x => x.Email)
            .NotEmpty().WithMessage("Email is required")
            .EmailAddress().WithMessage("Invalid email format")
            .MaximumLength(100).WithMessage("Email cannot exceed 100 characters")
            .Must(NotContainSqlInjection).WithMessage("Email contains invalid characters")
            .Must(NotContainXss).WithMessage("Email contains invalid characters");
        
        RuleFor(x => x.Password)
            .NotEmpty().WithMessage("Password is required")
            .MinimumLength(8).WithMessage("Password must be at least 8 characters")
            .MaximumLength(128).WithMessage("Password cannot exceed 128 characters")
            .Matches(@"[A-Z]").WithMessage("Password must contain at least one uppercase letter")
            .Matches(@"[a-z]").WithMessage("Password must contain at least one lowercase letter")
            .Matches(@"[0-9]").WithMessage("Password must contain at least one number")
            .Matches(@"[!@#$%^&*(),.?""':{}|<>]").WithMessage("Password must contain at least one special character");
        
        RuleFor(x => x.ConfirmPassword)
            .NotEmpty().WithMessage("Password confirmation is required")
            .Equal(x => x.Password).WithMessage("Passwords do not match");
    }
    
    private static bool NotContainSqlInjection(string? value)
    {
        if (string.IsNullOrEmpty(value)) return true;
        var lowerValue = value.ToLowerInvariant();
        return !SqlInjectionPatterns.Any(pattern => lowerValue.Contains(pattern));
    }
    
    private static bool NotContainSqlInjectionWithAt(string? value)
    {
        if (string.IsNullOrEmpty(value)) return true;
        var lowerValue = value.ToLowerInvariant();
        return !SqlInjectionPatternsWithAt.Any(pattern => lowerValue.Contains(pattern));
    }
    
    private static bool NotContainXss(string? value)
    {
        if (string.IsNullOrEmpty(value)) return true;
        var lowerValue = value.ToLowerInvariant();
        return !XssPatterns.Any(pattern => lowerValue.Contains(pattern));
    }
}
