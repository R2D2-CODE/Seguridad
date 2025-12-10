using FluentValidation;
using SafeVault.Core.DTOs;

namespace SafeVault.Core.Validators;

/// <summary>
/// Validator for login requests.
/// Implements strict validation to prevent injection attacks.
/// </summary>
public class LoginRequestValidator : AbstractValidator<LoginRequest>
{
    // Dangerous SQL injection patterns to detect
    private static readonly string[] SqlInjectionPatterns = 
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
    
    public LoginRequestValidator()
    {
        RuleFor(x => x.Username)
            .NotEmpty().WithMessage("Username is required")
            .MinimumLength(3).WithMessage("Username must be at least 3 characters")
            .MaximumLength(50).WithMessage("Username cannot exceed 50 characters")
            .Matches(@"^[a-zA-Z0-9_]+$").WithMessage("Username can only contain letters, numbers, and underscores")
            .Must(NotContainSqlInjection).WithMessage("Username contains invalid characters")
            .Must(NotContainXss).WithMessage("Username contains invalid characters");
        
        RuleFor(x => x.Password)
            .NotEmpty().WithMessage("Password is required")
            .MinimumLength(8).WithMessage("Password must be at least 8 characters")
            .MaximumLength(128).WithMessage("Password cannot exceed 128 characters");
    }
    
    private static bool NotContainSqlInjection(string? value)
    {
        if (string.IsNullOrEmpty(value)) return true;
        var lowerValue = value.ToLowerInvariant();
        return !SqlInjectionPatterns.Any(pattern => lowerValue.Contains(pattern));
    }
    
    private static bool NotContainXss(string? value)
    {
        if (string.IsNullOrEmpty(value)) return true;
        var lowerValue = value.ToLowerInvariant();
        return !XssPatterns.Any(pattern => lowerValue.Contains(pattern));
    }
}
