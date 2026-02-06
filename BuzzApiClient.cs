using Microsoft.Extensions.Logging;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;

namespace BuzzAPISample
{
    /// <summary>
    /// Makes requests to a Buzz API server.
    /// </summary>
    public class BuzzApiClient
    {
        private const int _retriesToMake = 5;
        private static readonly TimeSpan _initialWaitDuration = TimeSpan.FromMilliseconds(1000);
        private static readonly TimeSpan _maxRetryWaitDuration = TimeSpan.FromMilliseconds(64000);

        /// <summary>
        /// The <see cref="ILogger{TCategoryName}"/> instance to use for logging for this instance.
        /// </summary>
        private readonly ILogger<BuzzApiClient>? _logger;

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
        /// Create a BuzzApiClient
        /// </summary>
        /// <param name="logger">An <see cref="ILogger{TCategoryName}"/> to use for logging.</param>
        /// <param name="serverUrl">The URL of the server, including the protocol, and excluding trailing '/'</param>
        /// <param name="userAgent">The user agent to send on requests</param>
        /// <param name="verbose">Include verbose logging</param>
        /// <param name="timeout">Timeout in milliseconds for requests</param>
        public BuzzApiClient(ILogger<BuzzApiClient>? logger, string serverUrl, string userAgent, bool verbose = false, int timeout = 600000)
        {
            _logger = logger;

            ServerUrl = serverUrl;
            UserAgent = userAgent;
            Verbose = verbose;
            Timeout = timeout;

            _httpClient = new();
            _httpClient.DefaultRequestHeaders.Add("User-Agent", UserAgent);
            _httpClient.Timeout = TimeSpan.FromMilliseconds(Timeout);

            _autoLoginEnabled = false;
            _autoLoginUserspace = string.Empty;
            _autoLoginUsername = string.Empty;
            _autoLoginPassword = string.Empty;
        }

        /// <summary>
        /// Create a BuzzApiClient that automatically logs in, and will re-login if the current session expires
        /// </summary>
        /// <param name="serverUrl">The URL of the server, including the protocol, and excluding trailing '/'</param>
        /// <param name="userAgent">The user agent to send on requests</param>
        /// <param name="userspace">The userspace of the user to login</param>
        /// <param name="username">The user's username</param>
        /// <param name="password">The user's password</param>
        /// <param name="verbose">Include verbose logging</param>
        /// <param name="timeout">Timeout in milliseconds for requests</param>
        public BuzzApiClient(string serverUrl, string userAgent, string userspace, string username, string password, 
            bool verbose = false, int timeout = 600000)
        {
            if (string.IsNullOrEmpty(userspace) || string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
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

            throw new Exception("This method can only be used if the instance of BuzzApiClient was created with auto login");
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
            Token = tokenNode?.ToString();

            return responseJson;
        }

        /// <summary>
        /// Verify that the Json response indicates success
        /// </summary>
        /// <param name="responseJson">The json to verify</param>
        /// <param name="checkChildResponses">If VerifyResponse should check child responses. These are returned in APIs that can do multiple things, like CreateUsers which can make multiple users.</param>
        /// <returns>Verified and non-null json</returns>
        public JsonNode VerifyResponse(JsonNode? responseJson, bool checkChildResponses = true)
        {
            if (responseJson == null)
            {
                _logger?.LogError("Buzz API call failed. Expected response.code to be OK, found: null");
                throw new ArgumentException("Buzz API call failed. Expected response.code to be OK, found: null");
            }

            JsonNode jsonToVerify = responseJson;
            JsonNode? childResponse = responseJson["response"];
            if (childResponse is not null)
            {
                jsonToVerify = childResponse;
            }

            if (jsonToVerify["code"]?.ToString() != "OK")
            {
                string responseText = responseJson?.ToString() ?? "";
                _logger?.LogError("Buzz API call failed. Expected response.code to be OK, found: {ResponseText}", responseText);
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
                _logger?.LogInformation($"Attempting to login");
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
                _logger?.LogTrace($"Attempting to re-login because the request returned code \"NoAuthentication\"");
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
            TimeSpan baseWaitDuration = _initialWaitDuration;

            while (true)
            {
                RetryConditionHeaderValue? retryHeader = null;
                HttpResponseMessage? response = null;
                try
                {
                    HttpRequestMessage httpRequestMessage = new(httpMethod, requestUri);
                    if (content is not null)
                    {
                        httpRequestMessage.Content = content;
                    }
                    if (!string.IsNullOrEmpty(acceptsContentType))
                    {
                        httpRequestMessage.Headers.Accept.Add(new(acceptsContentType));
                    }

                    TraceRequest(requestUri, content);

                    response = await _httpClient.SendAsync(httpRequestMessage, cancel);
                    retryHeader = response.Headers.RetryAfter;

                    // API Time/Rate Limiting: 429 Too Many Requests (and 503 Service Unavailable) with Retry-After / X-RateLimit-* headers
                    if ((response.StatusCode == HttpStatusCode.TooManyRequests || response.StatusCode == HttpStatusCode.ServiceUnavailable) && retriesRemaining > 0)
                    {
                        TimeSpan waitDuration = GetRetryWaitDurationFromResponse(response, retryHeader, baseWaitDuration);
                        _logger?.LogWarning("Request rate/time limited. StatusCode: {StatusCode}, backing off for {WaitTimeMs} milliseconds (Retry-After or X-RateLimit-Reset), retries remaining: {RetriesRemaining}",
                            response.StatusCode, (int)waitDuration.TotalMilliseconds, retriesRemaining);
                        TraceRetry(new HttpRequestException($"Server returned {response.StatusCode}.", null, response.StatusCode), _retriesToMake - retriesRemaining + 1, waitDuration);
                        response.Dispose();
                        await Task.Delay(waitDuration, cancel);
                        retriesRemaining--;
                        baseWaitDuration = TimeSpan.FromMilliseconds(baseWaitDuration.TotalMilliseconds * 2);
                        continue;
                    }

                    if (response.StatusCode == HttpStatusCode.TooManyRequests || response.StatusCode == HttpStatusCode.ServiceUnavailable)
                    {
                        var statusCode = response.StatusCode;
                        response.Dispose();
                        throw new HttpRequestException($"Server returned {statusCode} (rate/time limited). No retries remaining.", null, statusCode);
                    }
                    response.EnsureSuccessStatusCode();
                    return response;
                }
                // catch exceptions here but only if there are retries remaining and the exception is one that allows retries
                catch (Exception e) when (retriesRemaining > 0 && (e is not HttpRequestException requestException || DoesStatusCodeAllowRetry(requestException.StatusCode)))
                {
                    response?.Dispose();
                    _logger?.LogTrace("Retryable exception invoking {Command} with {Method}: {ErrorType}, {ErrorMessage}", cmd, httpMethod, e.GetType(), e.Message);
                    // decide how long to wait before retrying based on any headers given by the server or if that's not there, the current base wait duration
                    TimeSpan waitDuration = GetRetryWaitDuration(retryHeader, baseWaitDuration);
                    TraceRetry(e, _retriesToMake - retriesRemaining + 1, waitDuration);
                    await Task.Delay(waitDuration, cancel);

                    retriesRemaining--;
                    baseWaitDuration = TimeSpan.FromMilliseconds(baseWaitDuration.TotalMilliseconds * 2);  // exponential back-off
                }
                finally
                {
                    response?.Dispose();
                }
            }
        }

        /// <summary>
        /// Computes backoff wait duration from API rate/time limiting response headers.
        /// Uses Retry-After first; if missing, uses X-RateLimit-Reset (seconds until window resets) per API docs.
        /// </summary>
        /// <returns>Duration to wait before retrying.</returns>
        private static TimeSpan GetRetryWaitDurationFromResponse(HttpResponseMessage response, RetryConditionHeaderValue? retryHeader, TimeSpan baseWaitDuration)
        {
            int waitFromRetryAfterMs = 0;
            if (retryHeader is not null)
            {
                if (retryHeader.Delta is not null)
                    waitFromRetryAfterMs = (int)retryHeader.Delta.Value.TotalMilliseconds;
                else if (retryHeader.Date is not null)
                    waitFromRetryAfterMs = Math.Max(0, (int)(retryHeader.Date.Value - DateTime.UtcNow).TotalMilliseconds);
            }
            if (waitFromRetryAfterMs > 0)
            {
                int cappedMs = Math.Max((int)baseWaitDuration.TotalMilliseconds, Math.Min((int)_maxRetryWaitDuration.TotalMilliseconds, waitFromRetryAfterMs));
                return TimeSpan.FromMilliseconds(cappedMs);
            }

            // X-RateLimit-Reset: seconds until the rate limit window ends (API Rate Limiting / Time Limiting docs)
            if (response.Headers.TryGetValues("X-RateLimit-Reset", out var resetValues) && resetValues.FirstOrDefault() is string resetSecsStr && int.TryParse(resetSecsStr, out int resetSecs) && resetSecs > 0)
            {
                int waitFromResetMs = resetSecs * 1000;
                int cappedMs = Math.Max((int)baseWaitDuration.TotalMilliseconds, Math.Min((int)_maxRetryWaitDuration.TotalMilliseconds, waitFromResetMs));
                return TimeSpan.FromMilliseconds(cappedMs);
            }
            int fallbackMs = Math.Min((int)_maxRetryWaitDuration.TotalMilliseconds, (int)baseWaitDuration.TotalMilliseconds + Random.Shared.Next(1, 1000));
            return TimeSpan.FromMilliseconds(fallbackMs);
        }

        /// <summary>
        /// Computes backoff wait duration from Retry-After header or exponential backoff.
        /// </summary>
        /// <returns>Duration to wait before retrying.</returns>
        private static TimeSpan GetRetryWaitDuration(RetryConditionHeaderValue? retryHeader, TimeSpan baseWaitDuration)
        {
            double baseMs = baseWaitDuration.TotalMilliseconds;
            double actualMs = baseMs;
            if (retryHeader is not null)
            {
                if (retryHeader.Delta is not null)
                    actualMs = Math.Max(actualMs, retryHeader.Delta.Value.TotalMilliseconds);
                else if (retryHeader.Date is not null)
                    actualMs = Math.Max(actualMs, (retryHeader.Date.Value - DateTime.UtcNow).TotalMilliseconds);
            }
            else
                actualMs = Math.Min(_maxRetryWaitDuration.TotalMilliseconds, actualMs + Random.Shared.Next(1, 1000));
            return TimeSpan.FromMilliseconds(Math.Min(_maxRetryWaitDuration.TotalMilliseconds, actualMs));
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

        private void TraceRetry(Exception e, int attempt, TimeSpan waitDuration)
        {
            int waitMs = (int)waitDuration.TotalMilliseconds;
            _logger?.LogDebug("Will make request retry #{Attempt} after {WaitTimeMs} milliseconds because of error: {ErrorMessage}", attempt, waitMs, e.Message);
        }

        private void TraceRequest(string requestUri, HttpContent? content)
        {
            _logger?.LogInformation("Request: {RequestUri}", requestUri);
            if (content is not null && content is StringContent)
            {
                string text = content.ReadAsStringAsync().Result;
                _logger?.LogDebug("Request content: {Content}", text[..Math.Min(text.Length, 1000)]);
            }
        }

        private void TraceResponse(JsonNode? json)
        {
            if (json is not null)
            {
                _logger?.LogDebug("Response with json content: {Content}", json.ToString());
            }
            else
            {
                _logger?.LogDebug("Response was empty or not json");
            }
        }
    }
}
