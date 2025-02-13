using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using WebApplication1.Model;

namespace WebApplication1.Model
{
    public class AuthDbContext : IdentityDbContext<ApplicationUser>
    {
        private readonly IConfiguration _configuration;

        public AuthDbContext(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            // Get the connection string from configuration and apply it to the options
            string connectionString = _configuration.GetConnectionString("AuthConnectionString");
            optionsBuilder.UseSqlServer(connectionString);
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // Call the base method first to ensure Identity configurations are applied
            base.OnModelCreating(modelBuilder);

            // Configure PreviousPasswords as an owned collection in ApplicationUser
            modelBuilder.Entity<ApplicationUser>()
                .OwnsMany(u => u.PreviousPasswords, passwords =>
                {
                    passwords.WithOwner().HasForeignKey("ApplicationUserId"); // This is for the navigation property
                    passwords.Property(p => p.HashedPassword).IsRequired();
                    passwords.Property(p => p.DateChanged).IsRequired();
                });
        }
    }
}
