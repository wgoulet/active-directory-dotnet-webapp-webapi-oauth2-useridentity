using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft;

namespace WebApp.Models
{
    public class CondorCertReqConverter : JsonConverter
    {
        public override bool CanWrite => false;
        public override bool CanRead => true;
        public override bool CanConvert(Type objectType)
        {
            return objectType == typeof(Condor.CertificateSigningRequest);
        }
        public override object ReadJson(JsonReader reader,Type objectType,object existingValue,JsonSerializer serializer)
        {
            var jsonObject = Newtonsoft.Json.Linq.JObject.Load(reader);
            Condor.CertificateSigningRequest certreq = new Condor.CertificateSigningRequest();
            JToken idVal = jsonObject["certificateRequests"][0]["id"];
            JToken statusVal = jsonObject["certificateRequests"][0]["status"];
            JToken certnameVal = jsonObject["certificateRequests"][0]["certificateName"];
            JToken createDateVal = jsonObject["certificateRequests"][0]["creationDate"];
            certreq.id = idVal.Value<string>();
            certreq.status = statusVal.Value<string>();
            certreq.certificateName = certnameVal.Value<string>();
            certreq.creationDate = DateTime.Parse(createDateVal.Value<string>());
            return certreq;
        }
        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            throw new NotImplementedException();
        }
    }
}