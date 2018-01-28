using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebApp.Models.AzureRMWebCertificates
{
    public class AzureRMWebCertificatesList
    {
        public AzureRMWebCertificatesList()
        {
            azureRMWebCertificates = new List<AzureRMWebCertificates>();
        }
        public List<AzureRMWebCertificates> azureRMWebCertificates { get; set; }
    }
    public class AzureRMWebCertificates
    {    
        public Value[] value { get; set; }
        public object nextLink { get; set; }
        public object id { get; set; }
    }

    public class Value
    {
        public string id { get; set; }
        public string name { get; set; }
        public string type { get; set; }
        public string location { get; set; }
        public Properties properties { get; set; }
    }

    public class Properties
    {
        public string friendlyName { get; set; }
        public string subjectName { get; set; }
        public string[] hostNames { get; set; }
        public object pfxBlob { get; set; }
        public object siteName { get; set; }
        public object selfLink { get; set; }
        public string issuer { get; set; }
        public DateTime issueDate { get; set; }
        public DateTime expirationDate { get; set; }
        public object password { get; set; }
        public string thumbprint { get; set; }
        public object valid { get; set; }
        public object toDelete { get; set; }
        public object cerBlob { get; set; }
        public object publicKeyHash { get; set; }
        public object hostingEnvironment { get; set; }
        public object hostingEnvironmentProfile { get; set; }
        public string keyVaultId { get; set; }
        public string keyVaultSecretName { get; set; }
        public string keyVaultSecretStatus { get; set; }
        public string webSpace { get; set; }
        public object serverFarmId { get; set; }
        public object tags { get; set; }
    }

}