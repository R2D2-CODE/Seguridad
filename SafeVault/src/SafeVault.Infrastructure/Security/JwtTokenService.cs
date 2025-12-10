using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Core.Entities;
using SafeVault.Core.Interfaces;

namespace SafeVault.Infrastructure.Security;

/// <summary>
/// JWT (JSON Web Token) service for generating authentication tokens.
/// 
/// SECURITY FEATURES:
/// - Uses HMAC-SHA256 for token signing
/// - Short token lifetime (default 1 hour) to limit exposure if compromised
/// - Includes essential claims for authorization (user ID, username, role)
/// - Token signature prevents tampering
/// 
/// Token Structure:
/// - Header: Algorithm and token type
/// - Payload: User claims (id, username, role, expiration)
/// - Signature: HMAC-SHA256 signature for verification
/// </summary>
public class JwtTokenService : IJwtTokenService
{
    private readonly IConfiguration _configuration;
    private readonly SymmetricSecurityKey _signingKey;
    private readonly int _tokenExpirationMinutes;
    
    public JwtTokenService(IConfiguration configuration)
    {
        _configuration = configuration;
        
        // Get the secret key from configuration
        // SECURITY: In production, this should be stored securely (Azure Key Vault, etc.)
        var secretKey = _configuration["Jwt:SecretKey"] 
            ?? throw new InvalidOperationException("JWT SecretKey is not configured");
        
        // Ensure the key is at least 256 bits (32 bytes) for HMAC-SHA256
        if (secretKey.Length < 32)
            throw new InvalidOperationException("JWT SecretKey must be at least 32 characters");
        
        _signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        
        // Get token expiration from configuration (default: 60 minutes)
        _tokenExpirationMinutes = int.Parse(_configuration["Jwt:ExpirationMinutes"] ?? "60");
    }
    
    /// <summary>
    /// Generates a JWT token for an authenticated user.
    /// 
    /// The token includes:
    /// - sub (subject): User ID
    /// - unique_name: Username
    /// - role: User's role for RBAC
    /// - iat (issued at): Token issue time
    /// - exp (expiration): Token expiration time
    /// </summary>
    public string GenerateToken(User user)
    {
        var claims = new List<Claim>
        {
            // Standard claims
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.UniqueName, user.Username),
            new(JwtRegisteredClaimNames.Email, user.Email),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            
            // Role claim for authorization
            new(ClaimTypes.Role, user.Role),
            new("role", user.Role), // Also include as custom claim for flexibility
            
            // Custom claims
            new("userId", user.Id.ToString())
        };
        
        var credentials = new SigningCredentials(_signingKey, SecurityAlgorithms.HmacSha256);
        
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = GetTokenExpiration(),
            Issuer = _configuration["Jwt:Issuer"],
            Audience = _configuration["Jwt:Audience"],
            SigningCredentials = credentials
        };
        
        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        
        return tokenHandler.WriteToken(token);
    }
    
    /// <summary>
    /// Gets the token expiration time.
    /// </summary>
    public DateTime GetTokenExpiration()
    {
        return DateTime.UtcNow.AddMinutes(_tokenExpirationMinutes);
    }
}
