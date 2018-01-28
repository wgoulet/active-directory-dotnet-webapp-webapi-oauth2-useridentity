using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebApp.Models
{
    public class ResourceGroups
    {   
        public Value[] value { get; set; }
    }

    public class Value
    {
        public string id { get; set; }
        public string name { get; set; }
        public string location { get; set; }
        public Properties properties { get; set; }
    }

    public class Properties
    {
        public string provisioningState { get; set; }
    }

}