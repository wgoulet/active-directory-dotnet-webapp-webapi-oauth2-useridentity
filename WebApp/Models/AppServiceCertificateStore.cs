namespace WebApp.Models
{
    using System;
    using System.Data.Entity;
    using System.Linq;

    public class AppServiceCertificateStore : DbContext
    {
        // Your context has been configured to use a 'AppServiceCertificateStore' connection string from your application's 
        // configuration file (App.config or Web.config). By default, this connection string targets the 
        // 'WebApp.Models.AppServiceCertificateStore' database on your LocalDb instance. 
        // 
        // If you wish to target a different database and/or database provider, modify the 'AppServiceCertificateStore' 
        // connection string in the application configuration file.
        public AppServiceCertificateStore()
            : base("name=AppServiceCertificateStore")
        {
        }

        // Add a DbSet for each entity type that you want to include in your model. For more information 
        // on configuring and using a Code First model, see http://go.microsoft.com/fwlink/?LinkId=390109.

        public virtual DbSet<AppServiceCertificate> appServiceCertificates { get; set; }
    }


}