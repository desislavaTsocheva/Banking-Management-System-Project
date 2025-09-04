using BankingManagmentApp.Data;
using BankingManagmentApp.Models;
using BankingManagmentApp.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
//Add DB
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

builder.Services.AddDefaultIdentity<Customers>(options => options.SignIn.RequireConfirmedAccount = false)
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();
builder.Services.AddDatabaseDeveloperPageExceptionFilter();
builder.Services.AddControllersWithViews();

//builder.Services.AddTransient<IEmailSender, EmailSender>();

builder.Services.Configure<IdentityOptions>(options =>
{
    options.SignIn.RequireConfirmedAccount = true;  // ensure email is confirmed
    options.Tokens.EmailConfirmationTokenProvider = TokenOptions.DefaultEmailProvider;
});


builder.Services.AddControllers(
    options =>
    options.SuppressImplicitRequiredAttributeForNonNullableReferenceTypes = true);

builder.Services.AddDistributedMemoryCache();

builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromSeconds(10);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.PrepareDataBase().Wait();

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.UseSession();
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.MapRazorPages();

//builder.Services.AddTransient<IEmailSender, EmailSender>();


app.Run();