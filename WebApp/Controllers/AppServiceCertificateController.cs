using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Data;
using System.Data.SqlClient;

// The following using statements were added for this sample.
using System.Configuration;
using System.Threading.Tasks;
using WebApp.Models;
using System.Security.Claims;
using System.Globalization;
using System.Net.Http;
using System.Net.Http.Headers;
using Newtonsoft.Json;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Cookies;
using System.Runtime.Serialization.Formatters.Binary;
using System.IO;
using System.Net;
using WebApp.Models.KeyVault;

namespace WebApp.Controllers
{
    [Authorize]
    public class AppServiceCertificateController : Controller
    {
        OAuthDataStore model;
        AppServiceCertificateStore ascStore;
        string condorAPIKey;
        string condorURL;
        public AppServiceCertificateController()
        {
            model = new OAuthDataStore();
            ascStore = new AppServiceCertificateStore();
            string connectionString = "Server=VED2k12;Database=Secrets;Integrated Security = true";
            string queryString = "SELECT * FROM SecretEntries";
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                connection.Open();
                SqlCommand sqlCommand = new SqlCommand(queryString, connection);
                SqlDataReader reader = sqlCommand.ExecuteReader();
                while (reader.Read())
                {
                    if(reader.GetString(0) == "apikey")
                    {
                        condorAPIKey = reader.GetString(1);
                    }
                    if(reader.GetString(0) == "url")
                    {
                        condorURL = reader.GetString(1);
                    }
                }
                connection.Close();
            }
        }

        // POST: /AppServiceCertificate/ClearOAuth
        [HttpPost]
        public async Task<ActionResult> ClearOAuth()
        {
            model.OAuthTokens.RemoveRange(model.OAuthTokens);
            ascStore.appServiceCertificates.RemoveRange(ascStore.appServiceCertificates);
            var result = await model.SaveChangesAsync();
            result = await ascStore.SaveChangesAsync();
            return RedirectToAction("Index", "AppServiceCertificate", new { authError = "AuthorizationRequired" });
        }

        // POST: /AppServiceCertificate/GetRefreshTokenAndTest
        [HttpPost]
        public async Task<ActionResult> GetRefreshTokenAndTest()
        {

            string userObjectID = ClaimsPrincipal.Current.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier").Value;
            IEnumerable<OAuthTokenSet> query =
              from OAuthTokenSet in model.OAuthTokens where OAuthTokenSet.userId == userObjectID select OAuthTokenSet;
            OAuthTokenSet usertoken = query.First();
            model.OAuthTokens.Remove(usertoken);
            var result = await model.SaveChangesAsync();
            string dest = "https://login.microsoftonline.com/b3aa98fb-8679-40e4-a942-6047017aa1a4/oauth2/token";
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(dest);
            req.Method = "POST";
            req.ContentType = "application/x-www-form-urlencoded";
            string postData = String.Format("grant_type=refresh_token&refresh_token={0}&client_id={1}&client_secret={2}&resource={3}",
                usertoken.refreshToken, Startup.clientId, Startup.appKey, Startup.resourceGroupsId);
            System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
            byte[] bytes = encoding.GetBytes(postData);
            req.ContentLength = bytes.Length;
            Stream nStream = req.GetRequestStream();
            nStream.Write(bytes, 0, bytes.Length);
            nStream.Close();
            HttpWebResponse resp = (HttpWebResponse)req.GetResponse();
            System.Runtime.Serialization.Json.DataContractJsonSerializer json = new System.Runtime.Serialization.Json.DataContractJsonSerializer(typeof(OAuthTokenResponse));
            OAuthTokenResponse recvtoken = json.ReadObject(resp.GetResponseStream()) as OAuthTokenResponse;
            OAuthTokenSet token = new OAuthTokenSet();
            token.accessToken = recvtoken.access_token;
            token.tokenType = recvtoken.token_type;
            token.refreshToken = recvtoken.refresh_token;
            token.userId = userObjectID;
            token.accessTokenExpiry = DateTime.Now.AddSeconds(Convert.ToDouble(recvtoken.expires_in)).ToUniversalTime().ToString(DateTimeFormatInfo.CurrentInfo.UniversalSortableDateTimePattern);
            Random rnd = new Random();
            token.Id = rnd.Next();
            model.OAuthTokens.Add(token);
            result = await model.SaveChangesAsync();

            string requestUrl = String.Format(
                   CultureInfo.InvariantCulture,
                   Startup.graphUserUrl,
                   HttpUtility.UrlEncode(Startup.tenant));
            HttpClient client = new HttpClient();
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.accessToken);
            HttpResponseMessage response = await client.SendAsync(request);
            if (response.IsSuccessStatusCode)
            {
                ViewBag.RefreshTokenUsedOK = "true";
            }
            string responseString = await response.Content.ReadAsStringAsync();
            UserProfile profile = JsonConvert.DeserializeObject<UserProfile>(responseString);
            // Copy over only the fields recevied from GraphAPI
            profile.AccessToken = token.accessToken;
            profile.AccessTokenExpiry = token.accessTokenExpiry;
            profile.RefreshToken = token.refreshToken;
            return View("Index", profile);
        }

        // POST: /AppServiceCertificate/ReplaceCertificate
        public async Task<ActionResult> ReplaceCertificate(AppServiceCertificate ascModel,string authError)
        {
            OAuthTokenSet usertoken = new OAuthTokenSet();
            HttpClient client = null;           
            // If we have a replacement cert passed to us, persist that to the database.
            if(Request.HttpMethod == HttpMethod.Post.Method)
            {
                ascStore.appServiceCertificates.Add(ascModel);
                ascStore.SaveChanges();
            }
            string responseString = null;
            string userObjectID = ClaimsPrincipal.Current.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier").Value;
            Uri redirectUri = new Uri(Request.Url.GetLeftPart(UriPartial.Authority).ToString() + "/OAuth");
            string state = GenerateState(userObjectID, Request.Url.ToString());
            string msoauthUri = string.Format("{0}/oauth2/authorize?resource={1}&client_id={2}&response_type=code&redirect_uri={3}&state={4}",
                Startup.Authority, Url.Encode(Startup.keyVaultResourceUrl), Startup.clientId, Url.Encode(redirectUri.ToString()), state);
            ViewBag.AuthorizationUrl = msoauthUri;
            IEnumerable<OAuthTokenSet> query =
              from OAuthTokenSet in model.OAuthTokens where OAuthTokenSet.userId == userObjectID && OAuthTokenSet.resourceName == Startup.keyVaultResourceUrl select OAuthTokenSet;

            if (query.GetEnumerator().MoveNext() == false)
            {
                usertoken.state = state;
                usertoken.userId = userObjectID;
                usertoken.resourceName = Startup.keyVaultResourceUrl;
                model.OAuthTokens.Add(usertoken);
                await model.SaveChangesAsync();
                authError = "AuthorizationRequired";
                ViewBag.Error = "AuthorizationRequiredKV";
                return View(ascModel);
            }
            else
            {
                usertoken = query.First();
                authError = null;
                // If we were redirected here back from the OAuth /authorization endpoint
                // we need to redisplay the form instead of just processing the request.
                if(Request.HttpMethod == HttpMethod.Get.Method)
                {
                    IEnumerable<AppServiceCertificate> cquery =
                        from AppServiceCertificate in ascStore.appServiceCertificates where AppServiceCertificate.Replace == true select AppServiceCertificate;
                    return View(cquery.First());
                }
            }
            string kvname = ascModel.ReplacementName.Replace('.', '-');
            string requestUrl = String.Format(
                       CultureInfo.InvariantCulture,
                       Startup.keyVaultCreateCertificateUrl, Startup.keyVaultName, kvname);
            KeyVaultRequest keyVaultRequest = new KeyVaultRequest();
            keyVaultRequest.policy = new Models.KeyVault.Policy();
            keyVaultRequest.policy.x509_props = new X509_Props();
            keyVaultRequest.policy.x509_props.subject = String.Format("CN={0}", ascModel.ReplacementName);
            string postData = JsonConvert.SerializeObject(keyVaultRequest);
            System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
            byte[] bytes = encoding.GetBytes(postData);
            client = new HttpClient();
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, requestUrl);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", usertoken.accessToken);
            request.Content = new ByteArrayContent(bytes);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            HttpResponseMessage resp = await client.SendAsync(request);
            if (resp.StatusCode != HttpStatusCode.Accepted)
            {
                ViewBag.Error = "unauthorized";
                AppServiceCertificates ascs = new AppServiceCertificates();
                ascs.appServiceCertificates.Add(ascModel);
                return RedirectToAction("Index", "AppServiceCertificate");
            }
            else
            {

            }
            responseString = await resp.Content.ReadAsStringAsync();
            dynamic result = JsonConvert.DeserializeObject<dynamic>(responseString);
            // Working with dynamic type here so I don't have to import all the object model definitions
            // for each type returned by the KeyVault REST API.
            KeyVaultRequestResponse kvResponse = new KeyVaultRequestResponse();
            foreach(var item in result)
            {
                if(item.Name == "csr")
                {
                    kvResponse.csr = item.Value;
                }
                if(item.Name == "id")
                {
                    kvResponse.id = item.Value;
                }
                if(item.Name == "request_id")
                {
                    kvResponse.requestID = item.Value;
                }
            }
            // Submit CSR to Condor service
            string zoneinfo = "fee52da0-0b58-11e8-af01-13126b5652e8";
            WebApp.Models.Condor.CertificateSigningRequest req = new Models.Condor.CertificateSigningRequest();
            req.certificateSigningRequest = kvResponse.getCSRWithHeaders();
            req.zoneId = zoneinfo;
            JsonSerializerSettings serializerSettings = new JsonSerializerSettings();
            serializerSettings.NullValueHandling = NullValueHandling.Ignore;
            postData = JsonConvert.SerializeObject(req,serializerSettings);
            encoding = new System.Text.ASCIIEncoding();
            bytes = encoding.GetBytes(postData);
            client = new HttpClient();
            request = new HttpRequestMessage(HttpMethod.Post, String.Format("{0}/v1/certificaterequests",condorURL));
            request.Headers.Add("tppl-api-key", condorAPIKey);
            request.Content = new ByteArrayContent(bytes);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            resp = await client.SendAsync(request);
            // Now poll Condor API to wait for cert to be issued, then install in KeyVault by merging
            // with previously created request.
            responseString = await resp.Content.ReadAsStringAsync();
            Object temp = JsonConvert.DeserializeObject(responseString);
          
            JsonConverter converter = new CondorCertReqConverter();
            WebApp.Models.Condor.CertificateSigningRequest  certreqresp = JsonConvert.DeserializeObject<Models.Condor.CertificateSigningRequest>(responseString,converter);
            return RedirectToAction("Index", "AppServiceCertificate");
        }

        // GET: AppServiceCertificate
        public async Task<ActionResult> Index(string authError)
        {
            AppServiceCertificates appServiceCertificates = new AppServiceCertificates();
            OAuthTokenSet usertoken = new OAuthTokenSet();
            Models.AzureRMWebCertificates.AzureRMWebCertificatesList azureRMWebCertificatesList = new Models.AzureRMWebCertificates.AzureRMWebCertificatesList();
            Models.AzureRMWebSites.ResourceManagerWebSites resourceManagerWebSites = new Models.AzureRMWebSites.ResourceManagerWebSites();
            // Always setup the OAuth /authorize URI to use
            Uri redirectUri = new Uri(Request.Url.GetLeftPart(UriPartial.Authority).ToString() + "/OAuth");
            string userObjectID = ClaimsPrincipal.Current.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier").Value;
            string state = GenerateState(userObjectID, Request.Url.ToString());
            string msoauthUri = string.Format("{0}/oauth2/authorize?resource={1}&client_id={2}&response_type=code&redirect_uri={3}&state={4}",
                    Startup.Authority, Url.Encode(Startup.resourceGroupsId), Startup.clientId, Url.Encode(redirectUri.ToString()), state);
            ViewBag.AuthorizationUrl = msoauthUri;

            // If we are loaded and we have no credentials, we will create a UserToken object to store the state that we include
            // in the link we construct to the Authorization endpoint. Once the user completes authorization, the OAuthController 
            // will look up the user token that we created and fill it in with the tokens it obtains.
            if (authError != null)
            {
                usertoken.state = state;
                usertoken.userId = userObjectID;
                usertoken.resourceName = Startup.resourceGroupsId;
                model.OAuthTokens.Add(usertoken);
                await model.SaveChangesAsync();                
                return View(appServiceCertificates);
            }
            else
            {
                // Check local OAuthDataStore to see if we have previously cached OAuth bearer tokens for this user.
                IEnumerable<OAuthTokenSet> query =
                   from OAuthTokenSet in model.OAuthTokens where OAuthTokenSet.userId == userObjectID && OAuthTokenSet.resourceName == Startup.resourceGroupsId select OAuthTokenSet;

                if (query.GetEnumerator().MoveNext() == false)
                {
                    usertoken.state = state;
                    usertoken.userId = userObjectID;
                    usertoken.resourceName = Startup.resourceGroupsId;
                    model.OAuthTokens.Add(usertoken);
                    await model.SaveChangesAsync();
                    authError = "AuthorizationRequired";
                }
                else
                {
                    usertoken = query.First();
                    appServiceCertificates.AccessToken = usertoken.accessToken;
                    appServiceCertificates.RefreshToken = usertoken.refreshToken;
                    appServiceCertificates.AccessTokenExpiry = usertoken.accessTokenExpiry;
                    authError = null;


                    string requestUrl = String.Format(
                           CultureInfo.InvariantCulture,
                           Startup.resourceGroupsUrl,
                           HttpUtility.UrlEncode(Startup.subscriptionId));
                    HttpClient client = new HttpClient();
                    HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", usertoken.accessToken);
                    HttpResponseMessage response = await client.SendAsync(request);
                    string responseString = await response.Content.ReadAsStringAsync();
                    ResourceGroups resourceGroups = JsonConvert.DeserializeObject<ResourceGroups>(responseString);
                    foreach (Value v in resourceGroups.value)
                    {
                        requestUrl = String.Format(
                          CultureInfo.InvariantCulture,
                          Startup.resourceManagerWebSitesUrl,
                          HttpUtility.UrlEncode(Startup.subscriptionId),
                          HttpUtility.UrlEncode(v.name));
                        client = new HttpClient();
                        request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
                        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", usertoken.accessToken);
                        response = await client.SendAsync(request);
                        responseString = await response.Content.ReadAsStringAsync();
                        Models.AzureRMWebSites.ResourceManagerWebSiteInfo resourceManagerWebSiteInfo = JsonConvert.DeserializeObject<Models.AzureRMWebSites.ResourceManagerWebSiteInfo>(responseString);
                        resourceManagerWebSites.webSites.Add(resourceManagerWebSiteInfo);
                        AppServiceCertificate appServiceCertificate = new AppServiceCertificate();

                        foreach (Models.AzureRMWebSites.Value wsv in resourceManagerWebSiteInfo.value)
                        {
                            foreach (Models.AzureRMWebSites.Hostnamesslstate sslstate in wsv.properties.hostNameSslStates)
                            {
                                if (sslstate.sslState == 1)
                                {
                                    appServiceCertificate.SiteName = sslstate.name;
                                }
                            }
                        }
                        requestUrl = String.Format(
                          CultureInfo.InvariantCulture,
                          Startup.resourceManagerWebCertificatesUrl,
                          HttpUtility.UrlEncode(Startup.subscriptionId),
                          HttpUtility.UrlEncode(v.name));
                        client = new HttpClient();
                        request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
                        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", usertoken.accessToken);
                        response = await client.SendAsync(request);
                        responseString = await response.Content.ReadAsStringAsync();
                        Models.AzureRMWebCertificates.AzureRMWebCertificates azureRMWebCertificates = JsonConvert.DeserializeObject<Models.AzureRMWebCertificates.AzureRMWebCertificates>(responseString);
                        foreach (Models.AzureRMWebCertificates.Value wsc in azureRMWebCertificates.value)
                        {
                            appServiceCertificate.KeyVaultSecretName = wsc.properties.keyVaultSecretName;
                            appServiceCertificate.CertificateName = wsc.properties.subjectName;
                            appServiceCertificate.KeyVaultId = wsc.properties.keyVaultId;
                            appServiceCertificate.CertificateIssuer = wsc.properties.issuer;
                            appServiceCertificate.CertificateExpiration = wsc.properties.expirationDate;
                            appServiceCertificate.CertificateThumbprint = wsc.properties.thumbprint;
                            appServiceCertificate.CertificateHostnames = wsc.properties.hostNames;
                        }
                        appServiceCertificates.appServiceCertificates.Add(appServiceCertificate);
                    }
                }
                return View(appServiceCertificates);
            }

        }


        public string GenerateState(string userObjId, string requestUrl)
        {
            try
            {
                string stateGuid = Guid.NewGuid().ToString();
                ApplicationDbContext db = new ApplicationDbContext();
                db.UserStateValues.Add(new UserStateValue { stateGuid = stateGuid, userObjId = userObjId });
                db.SaveChanges();

                List<String> stateList = new List<String>();
                stateList.Add(stateGuid);
                stateList.Add(requestUrl);

                var formatter = new BinaryFormatter();
                var stream = new MemoryStream();
                formatter.Serialize(stream, stateList);
                var stateBits = stream.ToArray();

                return Url.Encode(Convert.ToBase64String(stateBits));
            }
            catch
            {
                return null;
            }

        }
    }
}