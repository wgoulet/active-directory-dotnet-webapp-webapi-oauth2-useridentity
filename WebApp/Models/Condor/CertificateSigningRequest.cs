using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebApp.Models.Condor
{
    public class RootObject
    {
        public RootObject()
        {
            creationDate = null;
            modificationDate = null;
        }
        public string certificateSigningRequest { get; set; }
        public string zoneId { get; set; }
        public string id { set; get; }
        public string companyId { set; get; }
        public string status { set; get; }
        public string errorInformation { set; get; }
        public string type { set; get; }
        public string code { set; get; }
        public string message { set; get; }
        public string args { set; get; }
        public string testcaCAConnector { set; get; }
        public string certificateName { set; get; }
        public string certificateOwnerUserId { set; get; }
        public CertificatePolicyIds certificatePolicyIds { set; get; }
        public string certificateProviderId { set; get; }
        public Product product { set; get; }
        public string certificateAuthority { set; get; }
        public string validationScopeId { set; get; }
        public string certificateType { set; get; }
        public string validityPeriod { set; get; }
        public string hashAlgorithm { set; get; }
        public string caconfigurationId { set; get; }
        public List<object> certificateIds { set; get; }
        public string subjectDN { set; get; }
        public string keyLength { set; get; }
        public string keyType { set; get; }
        public DateTime? creationDate { set; get; }
        public DateTime? modificationDate { set; get; }

    }

    public class CertificateSigningRequest
    {
        public CertificateSigningRequest()
        {
            creationDate = null;
            modificationDate = null;
        }
        public string certificateSigningRequest { get; set; }
        public string zoneId { get; set; }
        public string id { set; get; }
        public string companyId { set; get; }
        public string status { set; get; }
        public string errorInformation { set; get; }
        public string type { set; get; }
        public string code { set; get; }
        public string message { set; get; }
        public string args { set; get; }
        public string testcaCAConnector { set; get; }
        public string certificateName { set; get; }
        public string certificateOwnerUserId { set; get; }
        public CertificatePolicyIds certificatePolicyIds { set; get; }
        public string certificateProviderId { set; get; }
        public Product product { set; get; }
        public string certificateAuthority { set; get; }
        public string validationScopeId { set; get; }
        public string certificateType { set; get; }
        public string validityPeriod { set; get; }
        public string hashAlgorithm { set; get; }
        public string caconfigurationId { set; get; }
        public List<object> certificateIds { set; get; }
        public string subjectDN { set; get; }
        public string keyLength { set; get; }
        public string keyType { set; get; }
        public DateTime? creationDate { set; get; }
        public DateTime? modificationDate { set; get; }

    }
    public class ErrorInformation
    {
        public string type { get; set; }
        public Int64 code { get; set; }
        public string message { get; set; }
        public List<string> args { get; set; }
    }
    public class CertificatePolicyIds
    {
        public string CERTIFICATE_IDENTITY { get; set; }
        public string CERTIFICATE_USE { get; set; }
    }
    public class Product
    {
        public string certificateAuthority { get; set; }
        public string validationScopeId { get; set; }
        public string certificateType { get; set; }
        public string validityPeriod { get; set; }
        public string hashAlgorithm { get; set; }
        public string caconfigurationId { get; set; }
    }
}

