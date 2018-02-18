using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Org.BouncyCastle.Pkcs;

namespace WebApp.Models.KeyVault
{
    public class KeyVaultRequestResponse
    {
        public string requestID { get; set; }
        public string id { get; set; }
        public string csr { get; set; }
        public string getCSRWithHeaders()
        {
            Pkcs10CertificationRequest pkcs10CertificationRequest = new Pkcs10CertificationRequest(Convert.FromBase64String(csr));
            System.Text.StringBuilder stringBuilder = new System.Text.StringBuilder();
            System.IO.StringWriter stringWriter = new System.IO.StringWriter(stringBuilder);
            Org.BouncyCastle.OpenSsl.PemWriter pemWriter = new Org.BouncyCastle.OpenSsl.PemWriter(stringWriter);
            pemWriter.WriteObject(pkcs10CertificationRequest);
            pemWriter.Writer.Flush();
            return stringBuilder.ToString();
        }
    }
    public class KeyVaultRequest   
    {
        public Policy policy { get; set; }
    }

    public class Policy
    {
        public X509_Props x509_props { get; set; }
    }

    public class X509_Props
    {
        public string subject { get; set; }
    }

}