using System.Text;
using FluentValidation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Api.Middleware;
using SafeVault.Core.DTOs;
using SafeVault.Core.Entities;
using SafeVault.Core.Interfaces;
using SafeVault.Core.Validators;
using SafeVault.Infrastructure.Data;
using SafeVault.Infrastructure.Repositories;
using SafeVault.Infrastructure.Security;

var builder = WebApplication.CreateBuilder(args);

// ============================================================================
// SECURITY CONFIGURATION
// ============================================================================

// Configure JWT Authentication
var jwtSecretKey = builder.Configuration["Jwt:SecretKey"] 
    ?? "ThisIsASecureSecretKeyForSafeVaultAppThatIsAtLeast32Characters!";
var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "SafeVault";
var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "SafeVaultUsers";

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        // Validate the JWT signature
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecretKey)),
        
        // Validate the issuer (who created the token)
        ValidateIssuer = true,
        ValidIssuer = jwtIssuer,
        
        // Validate the audience (who the token is intended for)
        ValidateAudience = true,
        ValidAudience = jwtAudience,
        
        // Validate the token expiry
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero, // No tolerance for token expiry
        
        // Map the role claim correctly
        RoleClaimType = System.Security.Claims.ClaimTypes.Role
    };
    
    // Event handlers for logging authentication events
    options.Events = new JwtBearerEvents
    {
        OnAuthenticationFailed = context =>
        {
            var logger = context.HttpContext.RequestServices
                .GetRequiredService<ILogger<Program>>();
            logger.LogWarning("Authentication failed: {Error}", context.Exception.Message);
            return Task.CompletedTask;
        },
        OnTokenValidated = context =>
        {
            var logger = context.HttpContext.RequestServices
                .GetRequiredService<ILogger<Program>>();
            var userId = context.Principal?.FindFirst("userId")?.Value;
            logger.LogInformation("Token validated for user: {UserId}", userId);
            return Task.CompletedTask;
        }
    };
});

// Configure Authorization with Role-Based Access Control (RBAC)
builder.Services.AddAuthorization(options =>
{
    // Policy for Admin-only endpoints
    options.AddPolicy("AdminOnly", policy => 
        policy.RequireRole(Roles.Admin));
    
    // Policy for authenticated users
    options.AddPolicy("AuthenticatedUsers", policy => 
        policy.RequireAuthenticatedUser());
});

// ============================================================================
// DATABASE CONFIGURATION
// ============================================================================

// Use In-Memory database for demonstration (use SQL Server in production)
builder.Services.AddDbContext<SafeVaultDbContext>(options =>
    options.UseInMemoryDatabase("SafeVaultDb"));

// ============================================================================
// DEPENDENCY INJECTION - SECURITY SERVICES
// ============================================================================

// Register repositories
builder.Services.AddScoped<IUserRepository, UserRepository>();
builder.Services.AddScoped<IVaultRepository, VaultRepository>();

// Register security services
builder.Services.AddScoped<IPasswordHasher, PasswordHasher>();
builder.Services.AddScoped<IInputSanitizer, InputSanitizer>();
builder.Services.AddScoped<IJwtTokenService, JwtTokenService>();

// Register FluentValidation validators
builder.Services.AddScoped<IValidator<LoginRequest>, LoginRequestValidator>();
builder.Services.AddScoped<IValidator<RegisterRequest>, RegisterRequestValidator>();
builder.Services.AddScoped<IValidator<CreateVaultItemRequest>, VaultItemValidator>();
builder.Services.AddScoped<IValidator<UpdateVaultItemRequest>, UpdateVaultItemValidator>();

// ============================================================================
// API CONFIGURATION
// ============================================================================

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// Configure Swagger with JWT authentication support
builder.Services.AddSwaggerGen();

var app = builder.Build();

// ============================================================================
// MIDDLEWARE PIPELINE (Order matters for security!)
// ============================================================================

// 1. Global exception handler (catches all unhandled exceptions)
app.UseGlobalExceptionHandler();

// 2. Security headers (adds protective HTTP headers)
app.UseSecurityHeaders();

// 3. HTTPS redirection (enforces secure connections)
if (!app.Environment.IsDevelopment())
{
    app.UseHttpsRedirection();
}

// 4. Swagger UI for API documentation (development only in production)
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// 5. Authentication middleware (validates JWT tokens)
app.UseAuthentication();

// 6. Authorization middleware (enforces access policies)
app.UseAuthorization();

// 7. Map controller endpoints
app.MapControllers();

// ============================================================================
// SEED DATA FOR DEMO
// ============================================================================

// Seed an admin user for demonstration
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<SafeVaultDbContext>();
    var passwordHasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();
    
    // Create admin user if not exists
    if (!context.Users.Any(u => u.Username == "admin"))
    {
        context.Users.Add(new User
        {
            Username = "admin",
            Email = "admin@safevault.com",
            PasswordHash = passwordHasher.HashPassword("Admin@123!"),
            Role = Roles.Admin,
            CreatedAt = DateTime.UtcNow,
            IsActive = true
        });
        
        context.Users.Add(new User
        {
            Username = "testuser",
            Email = "test@safevault.com",
            PasswordHash = passwordHasher.HashPassword("User@123!"),
            Role = Roles.User,
            CreatedAt = DateTime.UtcNow,
            IsActive = true
        });
        
        await context.SaveChangesAsync();
    }
}

app.Run();

// Make Program class accessible for integration tests
public partial class Program { }
