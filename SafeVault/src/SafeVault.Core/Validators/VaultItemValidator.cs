using FluentValidation;
using SafeVault.Core.DTOs;

namespace SafeVault.Core.Validators;

/// <summary>
/// Validator for vault item creation and update requests.
/// Sanitizes content to prevent XSS attacks.
/// </summary>
public class VaultItemValidator : AbstractValidator<CreateVaultItemRequest>
{
    // Dangerous XSS patterns to detect
    private static readonly string[] XssPatterns = 
    [
        "<script", "</script", "javascript:", "vbscript:",
        "onload=", "onerror=", "onclick=", "onmouseover=",
        "<iframe", "<object", "<embed", "<style",
        "expression(", "eval(", "alert(", "document.cookie",
        "document.write", "window.location", "document.location"
    ];
    
    public VaultItemValidator()
    {
        RuleFor(x => x.Title)
            .NotEmpty().WithMessage("Title is required")
            .MinimumLength(1).WithMessage("Title must be at least 1 character")
            .MaximumLength(200).WithMessage("Title cannot exceed 200 characters")
            .Must(NotContainDangerousXss).WithMessage("Title contains potentially dangerous content");
        
        RuleFor(x => x.Content)
            .NotEmpty().WithMessage("Content is required")
            .MaximumLength(10000).WithMessage("Content cannot exceed 10000 characters")
            .Must(NotContainDangerousXss).WithMessage("Content contains potentially dangerous content");
        
        RuleFor(x => x.Category)
            .MaximumLength(100).WithMessage("Category cannot exceed 100 characters")
            .Must(NotContainDangerousXss).WithMessage("Category contains potentially dangerous content")
            .When(x => !string.IsNullOrEmpty(x.Category));
    }
    
    private static bool NotContainDangerousXss(string? value)
    {
        if (string.IsNullOrEmpty(value)) return true;
        var lowerValue = value.ToLowerInvariant();
        return !XssPatterns.Any(pattern => lowerValue.Contains(pattern));
    }
}

/// <summary>
/// Validator for vault item update requests.
/// </summary>
public class UpdateVaultItemValidator : AbstractValidator<UpdateVaultItemRequest>
{
    private static readonly string[] XssPatterns = 
    [
        "<script", "</script", "javascript:", "vbscript:",
        "onload=", "onerror=", "onclick=", "onmouseover=",
        "<iframe", "<object", "<embed", "<style",
        "expression(", "eval(", "alert(", "document.cookie"
    ];
    
    public UpdateVaultItemValidator()
    {
        RuleFor(x => x.Title)
            .NotEmpty().WithMessage("Title is required")
            .MinimumLength(1).WithMessage("Title must be at least 1 character")
            .MaximumLength(200).WithMessage("Title cannot exceed 200 characters")
            .Must(NotContainDangerousXss).WithMessage("Title contains potentially dangerous content");
        
        RuleFor(x => x.Content)
            .NotEmpty().WithMessage("Content is required")
            .MaximumLength(10000).WithMessage("Content cannot exceed 10000 characters")
            .Must(NotContainDangerousXss).WithMessage("Content contains potentially dangerous content");
        
        RuleFor(x => x.Category)
            .MaximumLength(100).WithMessage("Category cannot exceed 100 characters")
            .Must(NotContainDangerousXss).WithMessage("Category contains potentially dangerous content")
            .When(x => !string.IsNullOrEmpty(x.Category));
    }
    
    private static bool NotContainDangerousXss(string? value)
    {
        if (string.IsNullOrEmpty(value)) return true;
        var lowerValue = value.ToLowerInvariant();
        return !XssPatterns.Any(pattern => lowerValue.Contains(pattern));
    }
}
