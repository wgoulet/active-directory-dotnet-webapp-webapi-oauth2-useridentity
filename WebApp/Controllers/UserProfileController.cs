﻿//----------------------------------------------------------------------------------------------
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
            //var cleanupTask = Task.Run(() => model.OAuthTokens.RemoveRange(model.OAuthTokens));
            model.OAuthTokens.RemoveRange(model.OAuthTokens);
            var result = await model.SaveChangesAsync();
            return RedirectToAction("Index", "UserProfile",new { authError = "AuthorizationRequired" });
        }

        //
        // GET: /UserProfile/
        public async Task<ActionResult> Index(string authError)
        {
            UserProfile profile = null;
            AuthenticationContext authContext = null;
            AuthenticationResult result = null;
            bool reauth = false;
            string userObjectID = ClaimsPrincipal.Current.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier").Value;
            OAuthTokenSet token = new OAuthTokenSet();
            IEnumerable<OAuthTokenSet> query =
               from OAuthTokenSet in model.OAuthTokens where OAuthTokenSet.userId == userObjectID select OAuthTokenSet;

            if(!query.Any())
            {
                authError = "AuthorizationRequired";
            }
            

            try
            {
                ClientCredential credential = new ClientCredential(Startup.clientId, Startup.appKey);
                authContext = new AuthenticationContext(Startup.Authority, new TokenDbCache(userObjectID));

                if (authError != null)
                {
                    Uri redirectUri = new Uri(Request.Url.GetLeftPart(UriPartial.Authority).ToString() + "/OAuth");
                    string state = GenerateState(userObjectID, Request.Url.ToString());
                    ViewBag.AuthorizationUrl = await authContext.GetAuthorizationRequestUrlAsync(Startup.graphResourceId, Startup.clientId, redirectUri, UserIdentifier.AnyUser, state == null ? null : "&state=" + state);

                    profile = new UserProfile();
                    profile.DisplayName = " ";
                    profile.GivenName = " ";
                    profile.Surname = " ";
                    ViewBag.ErrorMessage = authError;
                    return View(profile);
                }

                result = await authContext.AcquireTokenSilentAsync(Startup.graphResourceId, credential, UserIdentifier.AnyUser);
            }
            catch (AdalException e)
            {
                if (e.ErrorCode == "failed_to_acquire_token_silently")
                {
                    // Capture error for handling outside of catch block
                    reauth = true;
                }
                else
                {
                    ViewBag.ErrorMessage = "Error while Acquiring Token from Cache.";
                    return View("Error");
                }
            }

            if (reauth) {
                // The user needs to re-authorize.  Show them a message to that effect.
                // If the user still has a valid session with Azure AD, they will not be prompted for their credentials.

                profile = new UserProfile();
                profile.DisplayName = " ";
                profile.GivenName = " ";
                profile.Surname = " ";
                ViewBag.ErrorMessage = "AuthorizationRequired";
                authContext = new AuthenticationContext(Startup.Authority);
                Uri redirectUri = new Uri(Request.Url.GetLeftPart(UriPartial.Authority).ToString() + "/OAuth");

                string state = GenerateState(userObjectID, Request.Url.ToString());

                ViewBag.AuthorizationUrl = await authContext.GetAuthorizationRequestUrlAsync(Startup.graphResourceId, Startup.clientId, redirectUri, UserIdentifier.AnyUser, state == null ? null : "&state=" + state);

                return View(profile);
            }
            

            try 
            {
                //
                // Call the Graph API and retrieve the user's profile.
                //
                string requestUrl = String.Format(
                    CultureInfo.InvariantCulture,
                    Startup.graphUserUrl,
                    HttpUtility.UrlEncode(result.TenantId));
                HttpClient client = new HttpClient();
                HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", result.AccessToken);
                HttpResponseMessage response = await client.SendAsync(request);

                //
                // Return the user's profile in the view.
                //
                if (response.IsSuccessStatusCode)
                {
                    string responseString = await response.Content.ReadAsStringAsync();
                    profile = JsonConvert.DeserializeObject<UserProfile>(responseString);
                    return View(profile);
                }
                else if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    //
                    // If the call failed, then drop the current access token and show the user an error indicating they might need to sign-in again.
                    //
                    authContext.TokenCache.Clear();

                    Uri redirectUri = new Uri(Request.Url.GetLeftPart(UriPartial.Authority).ToString() + "/OAuth");
                    string state = GenerateState(userObjectID, Request.Url.ToString());
                    ViewBag.AuthorizationUrl = await authContext.GetAuthorizationRequestUrlAsync(Startup.graphResourceId, Startup.clientId, redirectUri, UserIdentifier.AnyUser, state == null ? null : "&state=" + state);

                    profile = new UserProfile();
                    profile.DisplayName = " ";
                    profile.GivenName = " ";
                    profile.Surname = " ";
                    ViewBag.ErrorMessage = "UnexpectedError";
                    return View(profile);
                }

                ViewBag.ErrorMessage = "Error Calling Graph API.";
                return View("Error");
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