using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

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

namespace WebApp.Controllers
{
    [Authorize]
    public class AppServiceCertificateController : Controller
    {
        OAuthDataStore model;
        public AppServiceCertificateController()
        {
            model = new OAuthDataStore();
        }

        // POST: /AppServiceCertificate/ClearOAuth
        [HttpPost]
        public async Task<ActionResult> ClearOAuth()
        {
            model.OAuthTokens.RemoveRange(model.OAuthTokens);
            var result = await model.SaveChangesAsync();
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

        // GET: AppServiceCertificate
        public async Task<ActionResult> Index(string authError)
        {
            Models.AzureRMWebCertificates.AzureRMWebCertificatesList azureRMWebCertificatesList = new Models.AzureRMWebCertificates.AzureRMWebCertificatesList();
            Models.AzureRMWebSites.ResourceManagerWebSites resourceManagerWebSites = new Models.AzureRMWebSites.ResourceManagerWebSites();
            AppServiceCertificates appServiceCertificates = new AppServiceCertificates();
            OAuthTokenSet usertoken = null;
            string userObjectID = ClaimsPrincipal.Current.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier").Value;
            // Always setup the OAuth /authorize URI to use
            Uri redirectUri = new Uri(Request.Url.GetLeftPart(UriPartial.Authority).ToString() + "/OAuth");
            string state = GenerateState(userObjectID, Request.Url.ToString());
            string msoauthUri = string.Format("{0}/oauth2/authorize?resource={1}&client_id={2}&response_type=code&redirect_uri={3}&state={4}",
                Startup.Authority, Url.Encode(Startup.resourceGroupsId), Startup.clientId, Url.Encode(redirectUri.ToString()), state);
            ViewBag.AuthorizationUrl = msoauthUri;

            // Check local OAuthDataStore to see if we have previously cached OAuth bearer tokens for this user.
            IEnumerable<OAuthTokenSet> query =
               from OAuthTokenSet in model.OAuthTokens where OAuthTokenSet.userId == userObjectID select OAuthTokenSet;

            if (query.GetEnumerator().MoveNext() == false)
            {
                authError = "AuthorizationRequired";
            }
            else
            {
                usertoken = query.First();
                appServiceCertificates.AccessToken = usertoken.accessToken;
                appServiceCertificates.RefreshToken = usertoken.refreshToken;
                appServiceCertificates.AccessTokenExpiry = usertoken.accessTokenExpiry;
                authError = null;
            }

            if (authError == null)
            {
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
               foreach(Value v in resourceGroups.value)
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
                        foreach(Models.AzureRMWebSites.Hostnamesslstate sslstate in wsv.properties.hostNameSslStates)
                        {
                            if(sslstate.sslState == 1)
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
                    foreach(Models.AzureRMWebCertificates.Value wsc in azureRMWebCertificates.value)
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
                return View(appServiceCertificates);
            }
            else
            {
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