using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using WebApplication1.Model;
using WebApplication1.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Builder;
using OtpSharp; // Google Authenticator package
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();

// Register the correct DbContext for Identity
builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Register Identity services with AuthDbContext
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<AuthDbContext>()
    .AddDefaultTokenProviders(); // Enables 2FA token providers

builder.Services.ConfigureApplicationCookie(config =>
{
    config.LoginPath = "/Login";
});

builder.WebHost.UseUrls("https://localhost:7257");

builder.Services.AddHttpClient(); // Add HttpClient for API calls
builder.Services.AddScoped<ReCaptchaService>(); // Register ReCaptchaService

builder.Services.AddDataProtection(); // Registers IDataProtectionProvider
builder.Services.AddScoped<EncryptionService>(); // Registers EncryptionService

builder.Services.AddDistributedMemoryCache(); // Required for session storage

builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(1); // Session expires in 1 minute
    options.Cookie.HttpOnly = true; // Prevent client-side access
    options.Cookie.IsEssential = true; // Ensure session works without user consent
});

builder.Services.Configure<IdentityOptions>(options =>
{
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1); // Lockout duration
    options.Lockout.MaxFailedAccessAttempts = 3; // 3 failed attempts = lockout
    options.Lockout.AllowedForNewUsers = true;
});

builder.Services.AddControllersWithViews(options =>
{
    options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
});

builder.Services.AddScoped<PasswordService>();

// Register your own EmailSender as the implementation for WebApplication1.Services.IEmailSender
builder.Services.AddScoped<WebApplication1.Services.IEmailSender, WebApplication1.Services.EmailSender>();

builder.Services.Configure<SmtpSettings>(builder.Configuration.GetSection("SmtpSettings"));

// 🔥 Enable Two-Factor Authentication with Google Authenticator
builder.Services.Configure<IdentityOptions>(options =>
{
    options.SignIn.RequireConfirmedAccount = true; // Users must confirm email before logging in
    options.Tokens.AuthenticatorTokenProvider = TokenOptions.DefaultAuthenticatorProvider; // Enable Google Authenticator
});

// Register the GoogleAuthenticator service (used for QR Code generation)
builder.Services.AddScoped<GoogleAuthenticator>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseStatusCodePages(async context =>
{
    if (context.HttpContext.Response.StatusCode == 404)
    {
        // Redirect to the custom 404 page
        context.HttpContext.Response.Redirect("/Errors/custom404");
        await Task.CompletedTask; // Ensure Task is returned
    }
});


app.UseSession(); // Enable session middleware
app.UseWebSockets(); // Ensure WebSockets are enabled
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();
app.MapControllers();


app.Run();
