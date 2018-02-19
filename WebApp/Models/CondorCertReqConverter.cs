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
            JToken idVal = null;
            JToken statusVal = null;
            JToken certnameVal = null;
            JToken createDateVal = null;

            Condor.CertificateSigningRequest certreq = new Condor.CertificateSigningRequest();
            // When POSTing a request, the CondorAPI returns the request as an object in an array.
            // However, when querying for a specific request, it returns just a single object. So
            // we'll change how we deserialize based on the name of the object returned (certificateRequests if it is an array)
            if(jsonObject.Property("certificateRequests") != null)
            {
                idVal = jsonObject["certificateRequests"][0]["id"];
                statusVal = jsonObject["certificateRequests"][0]["status"];
                certnameVal = jsonObject["certificateRequests"][0]["certificateName"];
                createDateVal = jsonObject["certificateRequests"][0]["creationDate"];
            }
            else
            {
                idVal = jsonObject["id"];
                statusVal = jsonObject["status"];
                certnameVal = jsonObject["certificateName"];
                createDateVal = jsonObject["creationDate"];
            }
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