using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebApp.Models.KeyVault
{
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