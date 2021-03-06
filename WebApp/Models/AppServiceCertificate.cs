﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Data.Entity;

namespace WebApp.Models
{
    public class AppServiceCertificates 
    {
        public AppServiceCertificates()
        {
            appServiceCertificates = new List<AppServiceCertificate>();
        }
        public List<AppServiceCertificate> appServiceCertificates { set; get; }
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public string AccessTokenExpiry { get; set; }

    }
    public class AppServiceCertificate
    {
        public AppServiceCertificate()
        {
            CertificateHostnames = new List<string>();
        }
        public string CertificateName { get; set; }
        public string KeyVaultId { get; set; }
        public string KeyVaultSecretName { get; set; }
        public string CertificateIssuer { get; set; }
        public DateTime? CertificateExpiration { get; set; }
        public string CertificateThumbprint { get; set; }
        public string SiteName { get; set; }
        public ICollection<string> CertificateHostnames { get; set; }
        public string ReplacementName { get; set; }
        public bool Replace { get; set; }
        public int Id { get; set; }
    }
}