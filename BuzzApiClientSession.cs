using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;

namespace BuzzAPISample
{
    /// <summary>
    /// Makes requests to a Buzz API server.
    /// </summary>
    public class BuzzApiClientSession
    {
        private const int _retriesToMake = 5;
        private const int _initialWaitTime = 1000;
        private const int _maxRetryWaitTime = 64000;

        /// <summary>
        /// The URL of the server, including the protocol, and excluding trailing '/'
        /// </summary>
        public string ServerUrl { get; private set; }

        /// <summary>
        /// The user agent to send on requests
        /// </summary>
        public string UserAgent { get; private set; }

        /// <summary>
        /// Include verbose logging
        /// </summary>
        public bool Verbose { get; set; }

        /// <summary>
        /// Timeout in milliseconds for requests
        /// </summary>
        public int Timeout { get; private set; }

        /// <summary>
        /// The authentication token returned in login
        /// </summary>
        public string? Token { get; private set; }

        private readonly HttpClient _httpClient;
        private readonly bool _autoLoginEnabled;
        private readonly string _autoLoginUserspace;
        private readonly string _autoLoginUsername;
        private readonly string _autoLoginPassword;

        /// <summary>
        /// Create a BuzzApiClientSession
        /// </summary>
        /// <param name="serverUrl">The URL of the server, including the protocol, and excluding trailing '/'</param>
        /// <param name="userAgent">The user agent to send on requests</param>
        /// <param name="verbose">Include verbose logging</param>
        /// <param name="timeout">Timeout in milliseconds for requests</param>
        public BuzzApiClientSession(string serverUrl, string userAgent, bool verbose = false, int timeout = 600000)
        {
            ServerUrl = serverUrl;
            UserAgent = userAgent;
            Verbose = verbose;
            Timeout = timeout;

            _httpClient = new();
            _httpClient.DefaultRequestHeaders.Add("User-Agent", UserAgent);
            _httpClient.Timeout = TimeSpan.FromMilliseconds(Timeout);

            _autoLoginEnabled = false;
            _autoLoginUserspace = String.Empty;
            _autoLoginUsername = String.Empty;
            _autoLoginPassword = String.Empty;
        }

        /// <summary>
        /// Create a BuzzApiClientSession that automatically logs in, and will re-login if the session expires
        /// </summary>
        /// <param name="serverUrl">The URL of the server, including the protocol, and excluding trailing '/'</param>
        /// <param name="userAgent">The user agent to send on requests</param>
        /// <param name="userspace">The userspace of the user to login</param>
        /// <param name="username">The user's username</param>
        /// <param name="password">The user's password</param>
        /// <param name="verbose">Include verbose logging</param>
        /// <param name="timeout">Timeout in milliseconds for requests</param>
        public BuzzApiClientSession(string serverUrl, string userAgent, string userspace, string username, string password, 
            bool verbose = false, int timeout = 600000)
        {
            if (String.IsNullOrEmpty(userspace) || String.IsNullOrEmpty(username) || String.IsNullOrEmpty(password))
            {
                throw new Exception("userspace, username, and password are required for auto login");
            }

            ServerUrl = serverUrl;
            UserAgent = userAgent;
            Verbose = verbose;
            Timeout = timeout;

            _httpClient = new();
            _httpClient.DefaultRequestHeaders.Add("User-Agent", UserAgent);
            _httpClient.Timeout = TimeSpan.FromMilliseconds(Timeout);

            _autoLoginEnabled = true;
            _autoLoginUserspace = userspace;
            _autoLoginUsername = username;
            _autoLoginPassword = password;
        }

        /// <summary>
        /// Uses the auto login user information to call the login3 API and set the token
        /// </summary>
        /// <param name="cancel">Cancellation token</param>
        /// <returns>The json returned from the login API</returns>
        public async ValueTask<JsonNode> Login(CancellationToken cancel = default)
        {
            if (_autoLoginEnabled)
            {
                return await Login(_autoLoginUserspace, _autoLoginUsername, _autoLoginPassword, cancel);
            }

            throw new Exception("This method can only be used if the instance of BuzzApiClientSession was created with auto login");
        }

        /// <summary>
        /// Calls the login3 API and sets the token
        /// </summary>
        /// <param name="userspace">The userspace of the user to login</param>
        /// <param name="username">The user's username</param>
        /// <param name="password">The user's password</param>
        /// <param name="cancel">Cancellation token</param>
        /// <returns>The json returned from the login API</returns>
        public async ValueTask<JsonNode> Login(string userspace, string username, string password, CancellationToken cancel = default)
        {
            var loginJson = new JsonObject
            {
                ["request"] = new JsonObject
                    {
                        ["cmd"] = "login3",
                        ["username"] = $"{userspace}/{username}",
                        ["password"] = password
                }
            };

            JsonNode responseJson = VerifyResponse(await JsonRequest(HttpMethod.Post, json: loginJson, includeToken: false, cancel: cancel));

            JsonNode? tokenNode = responseJson["user"]?["token"];
            Token = tokenNode is not null ? tokenNode.ToString() : null;

            return responseJson;
        }

        /// <summary>
        /// Calls the logout API
        /// </summary>
        /// <param name="cancel">Cancellation token</param>
        /// <returns>The json returned from the logout API</returns>
        public async ValueTask<JsonNode> Logout(CancellationToken cancel = default)
        {
            var loginJson = new JsonObject
            {
                ["request"] = new JsonObject
                {
                    ["cmd"] = "logout"
                }
            };

            JsonNode responseJson = VerifyResponse(await JsonRequest(HttpMethod.Post, json: loginJson, cancel: cancel));
            return responseJson;
        }

        /// <summary>
        /// Verify that the Json response indicates success
        /// </summary>
        /// <param name="responseJson">The json to verify</param>
        /// <param name="checkChildResponses">If VerifyResponse should check child responses. These are returned in APIs that can do multiple things, like CreateUsers which can make multiple users.</param>
        /// <returns>Verified and non-null json</returns>
        public static JsonNode VerifyResponse(JsonNode? responseJson, bool checkChildResponses = true)
        {
            _ = responseJson ?? throw new ArgumentException($"Buzz API call failed. Expected response.code to be OK, found: null");

            JsonNode jsonToVerify = responseJson;
            JsonNode? childResponse = responseJson["response"];
            if (childResponse is not null)
            {
                jsonToVerify = childResponse;
            }

            if (jsonToVerify["code"]?.ToString() != "OK")
            {
                string responseText = responseJson?.ToString() ?? "";
                throw new Exception($"Buzz API call failed. Expected response.code to be OK, found: {responseText}");
            }

            if (checkChildResponses)
            {
                JsonArray? responses = jsonToVerify["responses"]?["response"] as JsonArray;
                if (responses is not null)
                {
                    foreach (var response in responses)
                    {
                        VerifyResponse(response);
                    }
                }
            }
            return jsonToVerify;
        }

        /// <summary>
        /// Make a request to an API that returns Json
        /// </summary>
        /// <param name="httpMethod">The http method to use for the requests</param>
        /// <param name="cmd">The API call to make - for example, getuser2</param>
        /// <param name="parameters">Parameters to pass on the query string</param>
        /// <param name="json">Json to send as POST data</param>
        /// <param name="includeToken">Include the authentication token as a parameter</param>
        /// <param name="cancel">Cancellation token</param>
        /// <returns>The json returned from API call</returns>
        public async ValueTask<JsonNode?> JsonRequest(HttpMethod httpMethod, string? cmd = null, string? parameters = null, JsonNode? json = null,
            bool includeToken = true, CancellationToken cancel = default)
        {
            if (_autoLoginEnabled && includeToken && Token is null)
            {
                if (Verbose)
                {
                    Log($"Attempting to login");
                }
                await Login(cancel);
            }

            HttpContent? content = json is null ? null : new StringContent(json.ToJsonString(), Encoding.UTF8, "application/json");
            HttpResponseMessage response = await RequestWithRetry(httpMethod, cmd, parameters, content, includeToken, cancel:cancel);
            JsonNode? responseNode = JsonNode.Parse(await response.Content.ReadAsStreamAsync(cancel));
            TraceResponse(responseNode);

            // If the token expired, attempt to login and retry the request
            if (_autoLoginEnabled &&
                includeToken && 
                Token is not null && 
                responseNode?["response"]?["code"]?.ToString() == "NoAuthentication")
            {
                if (Verbose)
                {
                    Log($"Attempting to re-login because the request returned code \"NoAuthentication\"");
                }
                await Login(cancel);
                response = await RequestWithRetry(httpMethod, cmd, parameters, content, includeToken, cancel: cancel);
                responseNode = JsonNode.Parse(await response.Content.ReadAsStreamAsync(cancel));
                TraceResponse(responseNode);
            }
            return responseNode;
        }

        private async ValueTask<HttpResponseMessage> RequestWithRetry(HttpMethod httpMethod, string? cmd, string? parameters, HttpContent? content, 
            bool includeToken = true, string acceptsContentType = "application/json", CancellationToken cancel = default)
        {
            if (includeToken && Token is not null)
            {
                parameters = ((parameters is not null) ? $"{parameters}&" : "") + $"_token={Token}";
            }
            string requestUri = ServerUrl + "/cmd" + (cmd is not null ? $"/{cmd}" : "") + (parameters is not null ? $"?{parameters}" : "");

            int retriesRemaining = _retriesToMake;
            int baseWaitTime = _initialWaitTime;

            while (true)
            {
                RetryConditionHeaderValue? retryHeader = null;
                try
                {
                    HttpRequestMessage httpRequestMessage = new(httpMethod, requestUri);
                    if (content is not null)
                    {
                        httpRequestMessage.Content = content;
                    }
                    if (!String.IsNullOrEmpty(acceptsContentType))
                    {
                        httpRequestMessage.Headers.Accept.Add(new(acceptsContentType));
                    }

                    TraceRequest(requestUri, content);

                    HttpResponseMessage? response = await _httpClient.SendAsync(httpRequestMessage, cancel);
                    retryHeader = response.Headers.RetryAfter;
                    response.EnsureSuccessStatusCode();
                    if (response.Headers.RetryAfter is not null)
                    {
                        throw new HttpRequestException("Request failed because it had a retry-after header", null, response.StatusCode);
                    }
                    return response;
                }
                catch (Exception e)
                {
                    if (retriesRemaining <= 0 || 
                        (e is HttpRequestException requestException && 
                            !DoesStatusCodeAllowRetry(requestException.StatusCode)))
                    {
                        throw;
                    }

                    int waitTime = GetRetryWaitTime(baseWaitTime, retryHeader);
                    TraceRetry(e, _retriesToMake - retriesRemaining + 1, waitTime);
                    await Task.Delay(waitTime, cancel);

                    retriesRemaining--;
                    baseWaitTime *= 2;
                }
            }
        }

        private static int GetRetryWaitTime(int baseWaitTime, RetryConditionHeaderValue? retryHeader)
        {
            int actualWaitTime = baseWaitTime;
            if (retryHeader is not null)
            {
                if (retryHeader.Delta is not null)
                {
                    actualWaitTime = Math.Max(actualWaitTime, (int)retryHeader.Delta.Value.TotalMilliseconds);
                }
                else if (retryHeader.Date is not null)
                {
                    actualWaitTime = Math.Max(actualWaitTime, (int)(DateTime.UtcNow - retryHeader.Date.Value).TotalMilliseconds);
                }
            }
            actualWaitTime += Math.Min(_maxRetryWaitTime, actualWaitTime + (new Random()).Next(1, 1000));
            return actualWaitTime;
        }

        private static bool DoesStatusCodeAllowRetry(HttpStatusCode? statusCode)
        {
            return statusCode switch
            {
                // Client errors to not retry
                HttpStatusCode.BadRequest or 
                    HttpStatusCode.Unauthorized or 
                    HttpStatusCode.PaymentRequired or 
                    HttpStatusCode.Forbidden or 
                    HttpStatusCode.MethodNotAllowed or 
                    HttpStatusCode.NotAcceptable or HttpStatusCode.ProxyAuthenticationRequired or 
                    HttpStatusCode.Gone or 
                    HttpStatusCode.LengthRequired or 
                    HttpStatusCode.PreconditionFailed or 
                    HttpStatusCode.RequestEntityTooLarge or 
                    HttpStatusCode.RequestUriTooLong or 
                    HttpStatusCode.UnsupportedMediaType or 
                    HttpStatusCode.RequestedRangeNotSatisfiable or 
                    HttpStatusCode.ExpectationFailed or 
                    HttpStatusCode.MisdirectedRequest or 
                    HttpStatusCode.UnprocessableEntity or 
                    HttpStatusCode.FailedDependency or 
                    HttpStatusCode.UpgradeRequired or 
                    HttpStatusCode.PreconditionRequired or 
                    HttpStatusCode.TooManyRequests or 
                    HttpStatusCode.RequestHeaderFieldsTooLarge or 
                    HttpStatusCode.UnavailableForLegalReasons 
                        => false,

                // Server errors to not retry
                HttpStatusCode.NotImplemented or 
                    HttpStatusCode.HttpVersionNotSupported or 
                    HttpStatusCode.VariantAlsoNegotiates or 
                    HttpStatusCode.LoopDetected or 
                    HttpStatusCode.NotExtended or 
                    HttpStatusCode.NetworkAuthenticationRequired 
                        => false,

                _ => true,
            };
        }

        private static void Log(string logString)
        {
            Console.WriteLine(logString);
        }

        private void TraceRetry(Exception e, int attempt, int waitTime)
        {
            if (Verbose)
            {
                Log($"Will make request retry #{attempt} after {waitTime}ms because of error: {e.Message}");
            }
        }

        private void TraceRequest(string requestUri, HttpContent? content)
        {
            if (Verbose)
            {
                Log($"Request: {requestUri}");
                if (content is not null && content is StringContent)
                {
                    string text = content.ReadAsStringAsync().Result;
                    Log("Request content:");
                    Log(text[..Math.Min(text.Length, 1000)]);
                }
            }
        }

        private void TraceResponse(JsonNode? json)
        {
            if (Verbose)
            {
                if (json is not null)
                {
                    Log("Response with json content:");
                    Log(json.ToString());
                }
                else
                {
                    Log("Response was empty or not json");
                }
            }
        }
    }
}
