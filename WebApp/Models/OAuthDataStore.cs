namespace WebApp.Models
{
    using System;
    using System.Data.Entity;
    using System.Linq;

    public class OAuthDataStore : DbContext
    {
        // Your context has been configured to use a 'OAuthDataStore' connection string from your application's 
        // configuration file (App.config or Web.config). By default, this connection string targets the 
        // 'WebApp.Models.OAuthDataStore' database on your LocalDb instance. 
        // 
        // If you wish to target a different database and/or database provider, modify the 'OAuthDataStore' 
        // connection string in the application configuration file.
        public OAuthDataStore()
            : base("name=OAuthDataStore")
        {
        }

        // Add a DbSet for each entity type that you want to include in your model. For more information 
        // on configuring and using a Code First model, see http://go.microsoft.com/fwlink/?LinkId=390109.


        public virtual DbSet<OAuthTokenSet> OAuthTokens { get; set; }
    }

    public class OAuthTokenSet
    {
        public int Id { get; set; }
        public string accessToken { get; set; }
        public string accessTokenExpiry { get; set; }
        public string tokenType { get; set; }
        public string refreshToken { get; set; }
        public string userId { get; set; }

    }
}