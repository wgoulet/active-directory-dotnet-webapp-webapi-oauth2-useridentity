using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebApp.Models
{
    public class AppServiceCertificate
    {
        public string CertificateName { get; set; }
        public string CertificateID { get; set; }
        public string KeyVaultSecretName { get; set; }
    }
}