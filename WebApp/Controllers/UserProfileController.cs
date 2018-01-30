//----------------------------------------------------------------------------------------------
//    Copyright 2014 Microsoft Corporation
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
//----------------------------------------------------------------------------------------------

using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Claims;
// The following using statements were added for this sample.
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using WebApp.Models;

namespace WebApp.Controllers
{
    [Authorize]
    public class UserProfileController : Controller
    {
        OAuthDataStore model;

        public UserProfileController()
        {
            model = new OAuthDataStore();
        }

        // POST: /UserProfile/ClearOAuth
        [HttpPost]
        public async Task<ActionResult> ClearOAuth()
        {
            model.OAuthTokens.RemoveRange(model.OAuthTokens);
            var result = await model.SaveChangesAsync();
            return RedirectToAction("Index", "UserProfile", new { authError = "AuthorizationRequired" });
        }

        // POST: /UserProfile/GetRefreshTokenAndTest
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
                usertoken.refreshToken,Startup.clientId,Startup.appKey, Startup.graphResourceId);
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
            token.resourceName = Startup.graphResourceId;
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
            if(response.IsSuccessStatusCode)
            {
                ViewBag.RefreshTokenUsedOK = "true";
            }
            string responseString = await response.Content.ReadAsStringAsync();
            UserProfile profile = JsonConvert.DeserializeObject<UserProfile>(responseString);
            // Copy over only the fields recevied from GraphAPI
            profile.AccessToken = token.accessToken;
            profile.AccessTokenExpiry = token.accessTokenExpiry;
            profile.RefreshToken = token.refreshToken;
            return View("Index",profile);
        }

        //
        // GET: /UserProfile/
        public async Task<ActionResult> Index(string authError)
        {
            UserProfile profile = new UserProfile();
          
            string userObjectID = ClaimsPrincipal.Current.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier").Value;
            // Always setup the OAuth /authorize URI to use
            Uri redirectUri = new Uri(Request.Url.GetLeftPart(UriPartial.Authority).ToString() + "/OAuth");
            string state = GenerateState(userObjectID, Request.Url.ToString());
            string msoauthUri = string.Format("{0}/oauth2/authorize?resource={1}&client_id={2}&response_type=code&redirect_uri={3}&state={4}",
                Startup.Authority, Url.Encode(Startup.graphResourceId), Startup.clientId, Url.Encode(redirectUri.ToString()), state);
            ViewBag.AuthorizationUrl = msoauthUri;
            // Check local OAuthDataStore to see if we have previously cached OAuth bearer tokens for this user.
            IEnumerable<OAuthTokenSet> query =
               from OAuthTokenSet in model.OAuthTokens where OAuthTokenSet.userId == userObjectID && OAuthTokenSet.state == state select OAuthTokenSet;

            if (query.GetEnumerator().MoveNext() == false)
            {
                authError = "AuthorizationRequired";
            }
            else
            {
                OAuthTokenSet usertokens = query.First();
                profile.AccessToken = usertokens.accessToken;
                profile.RefreshToken = usertokens.refreshToken;
                profile.AccessTokenExpiry = usertokens.accessTokenExpiry;
                authError = null;
            }


            
            // Leaving this chunk of code alone, it generates the URL that the user will be redirected to when they
            // opt to sign in again. Per OAuth2 flow, this redirect will send the user to MS OAuth endpoint where they
            // will enter their creds. The resulting Authorization code is then used to get tokens. The OAuthController
            // will redirect users back to this controller, where we should be able to continue because the user completed 
            // OAuth ok.
            if (authError != null)
            {
                profile = new UserProfile();
                profile.DisplayName = " ";
                profile.GivenName = " ";
                profile.Surname = " ";
                ViewBag.ErrorMessage = authError;
                return View(profile);
            }

            OAuthTokenSet token = query.First();

            try
            {
                //
                // Call the Graph API and retrieve the user's profile.
                //
                string requestUrl = String.Format(
                    CultureInfo.InvariantCulture,
                    Startup.graphUserUrl,
                    HttpUtility.UrlEncode(Startup.tenant));
                HttpClient client = new HttpClient();
                HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.accessToken);
                HttpResponseMessage response = await client.SendAsync(request);

                //
                // Return the user's profile in the view.
                //
                if (response.IsSuccessStatusCode)
                {
                    string responseString = await response.Content.ReadAsStringAsync();
                    UserProfile tmp = JsonConvert.DeserializeObject<UserProfile>(responseString);
                    // Copy over only the fields recevied from GraphAPI
                    profile.DisplayName = tmp.DisplayName;
                    profile.GivenName = tmp.GivenName;
                    profile.Surname = tmp.Surname;
                    return View(profile);
                }
                else if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    //
                    // If the call failed, then drop the current access token and show the user an error indicating they might need to sign-in again.

                    model.OAuthTokens.RemoveRange(model.OAuthTokens);
                    model.SaveChanges();
                    
                   
                    
                    profile = new UserProfile();
                    profile.DisplayName = " ";
                    profile.GivenName = " ";
                    profile.Surname = " ";
                    ViewBag.ErrorMessage = "AuthorizationRequired";
                    return View(profile);
                }
                else
                {
                    ViewBag.ErrorMessage = "Error Calling Graph API.";
                    return View("Error");
                }

            }
            catch
            {
                ViewBag.ErrorMessage = "Error Calling Graph API.";
                return View("Error");
            }
        }

        /// Generate a state value using a random Guid value and the origin of the request.
        /// The state value will be consumed by the OAuth controller for validation and redirection after login.
        /// Here we store the random Guid in the database cache for validation by the OAuth controller.
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