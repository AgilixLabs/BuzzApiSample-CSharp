using Microsoft.Extensions.Logging;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using System.Xml.Linq;

namespace BuzzAPISample
{
    /// <summary>
    /// Makes requests to a Buzz API server.
    /// Supports OAuth 2.0 JWT client credentials (RFC 6749 + RFC 7523) and legacy password-based login.
    /// </summary>
    public class BuzzApiClient : IDisposable
    {
        private const int _retriesToMake = 5;
        private static readonly TimeSpan _initialWaitDuration = TimeSpan.FromMilliseconds(1000);
        private static readonly TimeSpan _maxRetryWaitDuration = TimeSpan.FromMilliseconds(64000);

        /// <summary>
        /// The longest server-directed wait (Retry-After / X-RateLimit-Reset) the client will sit out before retrying.
        /// Rate-limit windows are five minutes and the server adds jitter, so a Retry-After of several minutes is normal.
        /// Retrying before the server says to only burns quota, so a longer wait fails the request instead of retrying early.
        /// </summary>
        private static readonly TimeSpan _maxServerDirectedWait = TimeSpan.FromMinutes(10);

        /// <summary>
        /// Response codes the server uses in the XML/JSON envelope to say "slow down and retry later".
        /// Throttles are usually reported with HTTP 200 (the server wraps them for legacy clients), so the
        /// envelope code must be checked even when the HTTP status is a success.
        /// "TooManyRequests" is what every throttle collapses to when the server is set to report throttles generically;
        /// "Service Unavailable" is the code written when the server sheds load before a request is authenticated.
        /// </summary>
        private static readonly HashSet<string> s_throttleCodes = new(StringComparer.OrdinalIgnoreCase)
        {
            "TooManyRequests", "RetryLater", "LimitExceeded", "RateLimit", "TimeLimit",
            "ServerOverwhelmed", "BackendPressure", "Service Unavailable", "ServiceUnavailable",
        };

        /// <summary>
        /// The throttle codes that mean the server or a backend is overloaded (reported as 503) rather than
        /// that the caller exceeded a rate or time limit (reported as 429). Matched case-insensitively, like <see cref="s_throttleCodes"/>.
        /// </summary>
        private static readonly HashSet<string> s_overloadCodes = new(StringComparer.OrdinalIgnoreCase)
        {
            "ServerOverwhelmed", "BackendPressure", "Service Unavailable", "ServiceUnavailable",
        };

        /// <summary>
        /// UTC ticks before which no request from this client should be sent. Set whenever the server signals
        /// throttling or backend pressure, so concurrent requests sharing this client back off together
        /// instead of each discovering the throttle separately.
        /// </summary>
        private long _throttledUntilTicks;

        /// <summary>
        /// How far before token expiry to proactively refresh. Tokens are valid for 1 hour;
        /// refreshing 5 minutes early gives a comfortable window for slow networks or clock skew.
        /// </summary>
        private static readonly TimeSpan _oauthTokenRefreshMargin = TimeSpan.FromMinutes(5);

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
        /// The authentication token for API requests (Bearer token for OAuth, session token for password login)
        /// </summary>
        public string? Token { get; private set; }

        private readonly HttpClient _httpClient;

        // Password-based auto-login
        private readonly bool _autoLoginEnabled;
        private readonly string _autoLoginUserspace;
        private readonly string _autoLoginUsername;
        private readonly string _autoLoginPassword;

        // OAuth 2.0 (RFC 7523 JWT client credentials)
        private readonly bool _oauthEnabled;
        private readonly string _oauthUserId;
        private readonly string _oauthKid;
        private readonly RSA? _oauthRsa;
        private readonly string _oauthTokenEndpoint;
        private DateTimeOffset _oauthTokenExpiry;
        private readonly SemaphoreSlim _oauthTokenLock = new(1, 1);

        /// <summary>
        /// Create a BuzzApiClient.
        /// Call <see cref="Login(string, string, string, CancellationToken)"/> before making authenticated requests,
        /// or use the OAuth or auto-login constructor overloads instead.
        /// </summary>
        /// <param name="logger">An <see cref="ILogger{TCategoryName}"/> to use for logging.</param>
        /// <param name="serverUrl">The URL of the server, including the protocol, and excluding trailing '/'</param>
        /// <param name="userAgent">The user agent to send on requests</param>
        /// <param name="verbose">Include verbose logging</param>
        /// <param name="timeout">Timeout in milliseconds for requests</param>
        public BuzzApiClient(ILogger<BuzzApiClient>? logger, string serverUrl, string userAgent, bool verbose = false, int timeout = 600000)
        {
            _logger = logger;

            serverUrl = serverUrl.Trim().TrimEnd('/');
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

            _oauthEnabled = false;
            _oauthUserId = string.Empty;
            _oauthKid = string.Empty;
            _oauthRsa = null;
            _oauthTokenEndpoint = string.Empty;
        }

        /// <summary>
        /// Create a BuzzApiClient that automatically logs in with a username and password,
        /// and re-logs in if the session expires.
        /// </summary>
        /// <param name="serverUrl">The URL of the server, including the protocol, and excluding trailing '/'</param>
        /// <param name="userAgent">The user agent to send on requests</param>
        /// <param name="userspace">The userspace of the domain where the login user resides</param>
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

            serverUrl = serverUrl.Trim().TrimEnd('/');
            ServerUrl = serverUrl;
            UserAgent = userAgent;
            Verbose = verbose;
            Timeout = timeout;

            _httpClient = new();
            _httpClient.DefaultRequestHeaders.Add("User-Agent", UserAgent);
            _httpClient.Timeout = TimeSpan.FromMilliseconds(Timeout);

            _logger = null;
            _autoLoginEnabled = true;
            _autoLoginUserspace = userspace;
            _autoLoginUsername = username;
            _autoLoginPassword = password;

            _oauthEnabled = false;
            _oauthUserId = string.Empty;
            _oauthKid = string.Empty;
            _oauthRsa = null;
            _oauthTokenEndpoint = string.Empty;
        }

        /// <summary>
        /// Create a BuzzApiClient that authenticates via OAuth 2.0 JWT client credentials (RFC 6749 + RFC 7523).
        /// The client automatically requests and refreshes Bearer access tokens using a signed JWT assertion —
        /// no password is ever sent over the network.
        /// </summary>
        /// <param name="serverUrl">The URL of the server, including the protocol, and excluding trailing '/'</param>
        /// <param name="userAgent">The user agent to send on requests</param>
        /// <param name="oauthUserId">
        ///   The <c>userid</c> of the Application Identity account (returned by CreateUsers2 with
        ///   <c>type=applicationidentity</c>). Used as both the OAuth <c>client_id</c> and the
        ///   JWT <c>iss</c>/<c>sub</c> claims.
        ///   See the Buzz OAuth documentation for setup instructions.
        /// </param>
        /// <param name="oauthKid">
        ///   The Key ID (<c>kid</c>) chosen when registering the public key with Buzz.
        ///   Must match the <c>kid</c> path segment used in
        ///   <c>PUT {server}/api/users/{userid}/keys/{kid}</c>.
        /// </param>
        /// <param name="privateKey">
        ///   The RSA private key whose corresponding public key is registered with Buzz.
        ///   The caller owns this instance and is responsible for disposing it after the
        ///   <see cref="BuzzApiClient"/> is no longer in use.
        ///   Load it with:
        ///   <code>
        ///   using RSA rsa = RSA.Create();
        ///   rsa.ImportFromPem(File.ReadAllText("private_key.pem"));
        ///   </code>
        ///   Never commit the private key to source control.
        /// </param>
        /// <param name="verbose">Include verbose logging</param>
        /// <param name="timeout">Timeout in milliseconds for requests</param>
        /// <param name="logger">Optional logger for retry, rate-limit, and token events</param>
        public BuzzApiClient(string serverUrl, string userAgent, string oauthUserId, string oauthKid, RSA privateKey,
            bool verbose = false, int timeout = 600000, ILogger<BuzzApiClient>? logger = null)
        {
            if (string.IsNullOrEmpty(oauthUserId))
                throw new ArgumentException("oauthUserId is required", nameof(oauthUserId));
            if (string.IsNullOrEmpty(oauthKid))
                throw new ArgumentException("oauthKid is required", nameof(oauthKid));
            if (privateKey is null)
                throw new ArgumentNullException(nameof(privateKey));

            serverUrl = serverUrl.Trim().TrimEnd('/');
            ServerUrl = serverUrl;
            UserAgent = userAgent;
            Verbose = verbose;
            Timeout = timeout;

            _httpClient = new();
            _httpClient.DefaultRequestHeaders.Add("User-Agent", UserAgent);
            _httpClient.Timeout = TimeSpan.FromMilliseconds(Timeout);

            _logger = logger;
            _autoLoginEnabled = false;
            _autoLoginUserspace = string.Empty;
            _autoLoginUsername = string.Empty;
            _autoLoginPassword = string.Empty;

            _oauthEnabled = true;
            _oauthUserId = oauthUserId;
            _oauthKid = oauthKid;
            _oauthRsa = privateKey;
            _oauthTokenEndpoint = $"{serverUrl}/api/oauth/token";
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

            string? code = jsonToVerify["code"]?.ToString();
            if (code != "OK")
            {
                string responseText = CloneAndRedact(responseJson).ToString();
                _logger?.LogError("Buzz API call failed. Expected response.code to be OK, found: {ResponseText}", responseText);
                if (IsThrottleCode(code))
                    throw new BuzzApiThrottledException($"Buzz API call was throttled ({code}): {responseText}", code, responseJson, Array.Empty<int>(),
                        statusCode: ThrottleStatusCode(HttpStatusCode.OK, code));
                throw new Exception($"Buzz API call failed. Expected response.code to be OK, found: {responseText}");
            }

            if (checkChildResponses)
            {
                List<JsonNode?> responses = GetChildResponses(jsonToVerify);

                // Batch and multi-object commands report per-item throttles under an outer OK. Report them together
                // so the caller can resubmit just those items. Throttled batch items were rejected without running;
                // a multi-object row that hit BackendPressure (e.g. a database timeout) may have partially run.
                List<int> throttledIndexes = new();
                for (int i = 0; i < responses.Count; i++)
                {
                    if (IsThrottleCode(responses[i]?["code"]?.ToString()))
                        throttledIndexes.Add(i);
                }
                if (throttledIndexes.Count > 0)
                {
                    string? firstCode = responses[throttledIndexes[0]]?["code"]?.ToString();
                    _logger?.LogWarning("{ThrottledCount} of {ItemCount} items were throttled ({Code}); resubmit items {Indexes}",
                        throttledIndexes.Count, responses.Count, firstCode, string.Join(",", throttledIndexes));
                    throw new BuzzApiThrottledException(
                        $"{throttledIndexes.Count} of {responses.Count} items were throttled ({firstCode}). Resubmit the items at indexes {string.Join(",", throttledIndexes)}.",
                        firstCode, responseJson, throttledIndexes, statusCode: ThrottleStatusCode(HttpStatusCode.OK, firstCode));
                }

                foreach (var response in responses)
                {
                    VerifyResponse(response);
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
            if (includeToken)
            {
                if (_oauthEnabled && (Token is null || DateTimeOffset.UtcNow >= _oauthTokenExpiry - _oauthTokenRefreshMargin))
                {
                    await _oauthTokenLock.WaitAsync(cancel);
                    try
                    {
                        if (Token is null || DateTimeOffset.UtcNow >= _oauthTokenExpiry - _oauthTokenRefreshMargin)
                            await AuthenticateOAuth(cancel);
                    }
                    finally
                    {
                        _oauthTokenLock.Release();
                    }
                }
                else if (_autoLoginEnabled && Token is null)
                {
                    _logger?.LogInformation("Attempting to login");
                    await Login(cancel);
                }
            }

            using HttpContent? content = json is null ? null : new StringContent(json.ToJsonString(), Encoding.UTF8, "application/json");
            JsonNode? responseNode;
            bool authenticationRejected;
            try
            {
                responseNode = await RequestWithRetry(httpMethod, cmd, parameters, content, includeToken, cancel: cancel);
                TraceResponse(responseNode);
                authenticationRejected = GetResponseCode(responseNode) == "NoAuthentication";
            }
            // REST-style endpoints report an expired or revoked token as HTTP 401, possibly with no envelope
            catch (HttpRequestException e) when (e.StatusCode == HttpStatusCode.Unauthorized && includeToken && Token is not null && (_oauthEnabled || _autoLoginEnabled))
            {
                responseNode = null;
                authenticationRejected = true;
            }

            // If the token expired or was revoked, re-authenticate and retry the request once
            if (includeToken && Token is not null && authenticationRejected)
            {
                if (_oauthEnabled)
                {
                    _logger?.LogTrace("Re-authenticating via OAuth because the request returned code \"NoAuthentication\"");
                    await _oauthTokenLock.WaitAsync(cancel);
                    try
                    {
                        await AuthenticateOAuth(cancel);
                    }
                    finally
                    {
                        _oauthTokenLock.Release();
                    }
                }
                else if (_autoLoginEnabled)
                {
                    _logger?.LogTrace("Attempting to re-login because the request returned code \"NoAuthentication\"");
                    await Login(cancel);
                }
                else
                {
                    return responseNode;
                }
                // content is StringContent (ByteArrayContent-backed) so its stream rewinds on re-read — safe to reuse.
                responseNode = await RequestWithRetry(httpMethod, cmd, parameters, content, includeToken, cancel: cancel);
                TraceResponse(responseNode);
            }
            return responseNode;
        }

        /// <summary>
        /// Sends a request, retrying transient failures, and returns the parsed response envelope (XML or JSON, normalized to JSON).
        /// Throttling is recognized from the HTTP status (429/503) or from the envelope code, since the server
        /// usually reports throttles as HTTP 200 with a code like "TimeLimit" or "BackendPressure" in the body.
        /// </summary>
        private async ValueTask<JsonNode?> RequestWithRetry(HttpMethod httpMethod, string? cmd, string? parameters, HttpContent? content,
            bool includeToken = true, string acceptsContentType = "application/json", CancellationToken cancel = default)
        {
            // OAuth uses Authorization: Bearer header; password auth uses _token query parameter
            if (!_oauthEnabled && includeToken && Token is not null)
            {
                parameters = ((parameters is not null) ? $"{parameters}&" : "") + $"_token={Uri.EscapeDataString(Token)}";
            }
            string requestUri = ServerUrl + "/cmd" + (cmd is not null ? $"/{cmd}" : "") + (parameters is not null ? $"?{parameters}" : "");

            int retriesRemaining = _retriesToMake;
            TimeSpan baseWaitDuration = _initialWaitDuration;

            while (true)
            {
                await WaitForThrottleWindow(cancel);

                RetryConditionHeaderValue? retryHeader = null;
                try
                {
                    using HttpRequestMessage httpRequestMessage = new(httpMethod, requestUri);
                    if (_oauthEnabled && includeToken && Token is not null)
                    {
                        httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);
                    }
                    if (content is not null)
                    {
                        httpRequestMessage.Content = content;
                    }
                    if (!string.IsNullOrEmpty(acceptsContentType))
                    {
                        httpRequestMessage.Headers.Accept.Add(new(acceptsContentType));
                    }

                    TraceRequest(requestUri);

                    HttpResponseMessage sent;
                    try
                    {
                        sent = await _httpClient.SendAsync(httpRequestMessage, cancel);
                    }
                    finally
                    {
                        httpRequestMessage.Content = null; // detach shared content; caller owns its lifecycle
                    }
                    using HttpResponseMessage response = sent;
                    retryHeader = response.Headers.RetryAfter;

                    string body = await response.Content.ReadAsStringAsync(cancel);
                    // Parse strictly on success (a garbled success body is an error); on failure the envelope is optional.
                    string? mediaType = response.Content.Headers.ContentType?.MediaType;
                    JsonNode? envelope = response.IsSuccessStatusCode ? ParseEnvelope(body, mediaType) : TryParseEnvelope(body, mediaType);
                    string? code = GetResponseCode(envelope);

                    // API time/rate limiting and backend pressure: HTTP 429/503 (REST-style), or an envelope throttle code (usually with HTTP 200).
                    // Retry-After is sent either way; X-RateLimit-Reset (seconds until the window resets) is the fallback.
                    if (response.StatusCode == HttpStatusCode.TooManyRequests || response.StatusCode == HttpStatusCode.ServiceUnavailable || IsThrottleCode(code))
                    {
                        TimeSpan? serverWait = GetServerDirectedWait(response.Headers);
                        TimeSpan waitDuration = GetThrottleWaitDuration(serverWait, baseWaitDuration);
                        string? message = envelope?["response"]?["message"]?.ToString();
                        if (retriesRemaining > 0 && waitDuration <= _maxServerDirectedWait)
                        {
                            _logger?.LogWarning("Request throttled. StatusCode: {StatusCode}, Code: {Code}, Message: {Message}, Pressure: {PressureService} {PressureLevel}, backing off for {WaitTimeMs} milliseconds, retries remaining: {RetriesRemaining}",
                                (int)response.StatusCode, code, message, GetHeader(response.Headers, "X-Backend-Pressure-Service"), GetHeader(response.Headers, "X-Backend-Pressure-Level"),
                                (int)waitDuration.TotalMilliseconds, retriesRemaining);
                            ExtendThrottleWindow(waitDuration);
                            retriesRemaining--;
                            baseWaitDuration = TimeSpan.FromMilliseconds(baseWaitDuration.TotalMilliseconds * 2);
                            continue;   // the throttle window is awaited at the top of the loop
                        }
                        ExtendThrottleWindow(waitDuration < _maxServerDirectedWait ? waitDuration : _maxServerDirectedWait);
                        string reason = retriesRemaining > 0
                            ? $"server asked to wait {(int)waitDuration.TotalSeconds}s, longer than the {(int)_maxServerDirectedWait.TotalSeconds}s limit"
                            : "no retries remaining";
                        throw new BuzzApiThrottledException(
                            $"Buzz API request was throttled (HTTP {(int)response.StatusCode}, code {code ?? "none"}): {message} ({reason})",
                            code, envelope, Array.Empty<int>(), serverWait, ThrottleStatusCode(response.StatusCode, code));
                    }

                    if (response.IsSuccessStatusCode)
                    {
                        ExtendThrottleWindowForThrottledItems(envelope, response.Headers);
                        return envelope;
                    }

                    // A REST-style error status with an envelope (e.g. 400 BadRequest, 404 ResourceNotFound): return it so the
                    // caller sees the server's code and message, just as it would for the same error wrapped in HTTP 200.
                    // 401 is thrown instead so JsonRequest re-authenticates whether or not an envelope came with it.
                    if (code is not null && !DoesStatusCodeAllowRetry(response.StatusCode) && response.StatusCode != HttpStatusCode.Unauthorized)
                        return envelope;

                    throw new HttpRequestException($"Server returned {(int)response.StatusCode} {response.ReasonPhrase}{(code is not null ? $" (code {code})" : "")}.", null, response.StatusCode);
                }
                // catch exceptions here but only if there are retries remaining and the exception is one that allows retries.
                // A success body that fails to parse is not retried: the server already ran the command, and resending
                // a mutation (or a batch) could repeat it.
                catch (Exception e) when (retriesRemaining > 0 && e is not BuzzApiThrottledException && !IsParseException(e)
                    && (e is not HttpRequestException requestException || DoesStatusCodeAllowRetry(requestException.StatusCode)))
                {
                    _logger?.LogTrace("Retryable exception invoking {Command} with {Method}: {ErrorType}, {ErrorMessage}", cmd, httpMethod, e.GetType(), e.Message);
                    // decide how long to wait before retrying based on any headers given by the server or if that's not there, the current base wait duration
                    TimeSpan waitDuration = GetRetryWaitDuration(retryHeader, baseWaitDuration);
                    TraceRetry(e, _retriesToMake - retriesRemaining + 1, waitDuration);
                    await Task.Delay(waitDuration, cancel);

                    retriesRemaining--;
                    baseWaitDuration = TimeSpan.FromMilliseconds(baseWaitDuration.TotalMilliseconds * 2);  // exponential back-off
                }
            }
        }

        /// <summary>
        /// Requests a new Bearer access token from the OAuth token endpoint using a short-lived JWT client assertion
        /// signed with the registered RSA private key (RFC 7523).
        /// Called automatically by <see cref="JsonRequest"/> when a token is absent or nearing expiry.
        /// </summary>
        private async ValueTask AuthenticateOAuth(CancellationToken cancel = default)
        {
            _logger?.LogInformation("Requesting OAuth access token");

            int retriesRemaining = _retriesToMake;
            TimeSpan baseWaitDuration = _initialWaitDuration;
            while (true)
            {
                // Wait out any throttle window first, then build a fresh assertion on every attempt:
                // JWTs expire in 2 minutes and a throttle wait can be up to 10, so an assertion built
                // before the wait (or reused from an earlier attempt) could be past its exp claim.
                await WaitForThrottleWindow(cancel);
                string assertion = BuildClientAssertion(_oauthRsa!, _oauthUserId, _oauthKid, _oauthTokenEndpoint);
                var formFields = new[]
                {
                    new KeyValuePair<string, string>("grant_type",            "client_credentials"),
                    new KeyValuePair<string, string>("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                    new KeyValuePair<string, string>("client_assertion",      assertion),
                };

                RetryConditionHeaderValue? retryHeader = null;
                HttpResponseMessage? response = null;
                try
                {
                    using var formContent = new FormUrlEncodedContent(formFields);
                    response = await _httpClient.PostAsync(_oauthTokenEndpoint, formContent, cancel);
                    retryHeader = response.Headers.RetryAfter;

                    if (!response.IsSuccessStatusCode)
                    {
                        string body = await response.Content.ReadAsStringAsync(cancel);
                        // The token endpoint answers with RFC 6749 errors rather than the DLAP envelope:
                        // rate limits and backend pressure are 429/503 with error "temporarily_unavailable" and Retry-After.
                        string? oauthError = TryParseEnvelope(body, response.Content.Headers.ContentType?.MediaType)?["error"]?.ToString();
                        if (response.StatusCode == HttpStatusCode.TooManyRequests || response.StatusCode == HttpStatusCode.ServiceUnavailable || oauthError == "temporarily_unavailable")
                        {
                            TimeSpan? serverWait = GetServerDirectedWait(response.Headers);
                            TimeSpan wait = GetThrottleWaitDuration(serverWait, baseWaitDuration);
                            if (retriesRemaining > 0 && wait <= _maxServerDirectedWait)
                            {
                                _logger?.LogWarning("OAuth token request throttled ({StatusCode}, {Error}), backing off {WaitMs}ms, {Retries} retries remaining",
                                    (int)response.StatusCode, oauthError, (int)wait.TotalMilliseconds, retriesRemaining);
                                response.Dispose();
                                ExtendThrottleWindow(wait);
                                retriesRemaining--;
                                baseWaitDuration = TimeSpan.FromMilliseconds(baseWaitDuration.TotalMilliseconds * 2);
                                continue;   // the throttle window is awaited at the top of the loop
                            }
                            ExtendThrottleWindow(wait < _maxServerDirectedWait ? wait : _maxServerDirectedWait);
                            throw new BuzzApiThrottledException($"OAuth token request was throttled ({(int)response.StatusCode}): {body}",
                                oauthError, null, Array.Empty<int>(), serverWait, ThrottleStatusCode(response.StatusCode, null));
                        }
                        _logger?.LogError("OAuth token request failed: {StatusCode} {Body}", response.StatusCode, body);
                        throw new HttpRequestException($"OAuth token request failed ({response.StatusCode}): {body}", null, response.StatusCode);
                    }

                    JsonNode? tokenJson = await JsonNode.ParseAsync(await response.Content.ReadAsStreamAsync(cancel), cancellationToken: cancel);
                    string? accessToken = tokenJson?["access_token"]?.ToString();
                    if (string.IsNullOrEmpty(accessToken))
                        throw new Exception("OAuth token response did not contain an access_token.");

                    int expiresIn = 3600;
                    if (tokenJson?["expires_in"] is { } expiresInNode)
                    {
                        try { expiresIn = expiresInNode.GetValue<int>(); }
                        catch
                        {
                            if (int.TryParse(expiresInNode.ToString(), out int parsed) && parsed > 0)
                                expiresIn = parsed;
                        }
                    }
                    if (expiresIn <= 0)
                        expiresIn = 3600;
                    Token = accessToken;
                    _oauthTokenExpiry = DateTimeOffset.UtcNow.AddSeconds(expiresIn);
                    _logger?.LogInformation("OAuth token obtained, expires in {ExpiresIn}s", expiresIn);
                    response.Dispose();
                    return;
                }
                catch (Exception e) when (retriesRemaining > 0 && e is not BuzzApiThrottledException && (e is not HttpRequestException rex || DoesStatusCodeAllowRetry(rex.StatusCode)))
                {
                    response?.Dispose();
                    TimeSpan wait = GetRetryWaitDuration(retryHeader, baseWaitDuration);
                    _logger?.LogTrace("OAuth token request retrying after {ErrorType}: {Message}", e.GetType(), e.Message);
                    await Task.Delay(wait, cancel);
                    retriesRemaining--;
                    baseWaitDuration = TimeSpan.FromMilliseconds(baseWaitDuration.TotalMilliseconds * 2);
                }
                catch
                {
                    response?.Dispose();
                    throw;
                }
            }
        }

        /// <summary>
        /// Builds a signed JWT client assertion for the OAuth token endpoint (RFC 7523 §3).
        /// The JWT includes iss, sub, aud, iat, exp, and a unique jti to prevent replay attacks.
        /// Signed with RS256 (RSASSA-PKCS1-v1_5 + SHA-256).
        /// </summary>
        private static string BuildClientAssertion(RSA rsa, string userId, string kid, string tokenEndpoint)
        {
            var now = DateTimeOffset.UtcNow;

            // JWT header: algorithm and key ID
            var header = new JsonObject { ["alg"] = "RS256", ["kid"] = kid, ["typ"] = "JWT" };

            // JWT payload: identity claims
            var payload = new JsonObject
            {
                ["iss"] = userId,                                                       // issuer = client
                ["sub"] = userId,                                                       // subject = client (must equal iss per RFC 7523)
                ["aud"] = tokenEndpoint,                                                // audience = token endpoint URL
                ["iat"] = now.ToUnixTimeSeconds(),                                      // issued at
                ["exp"] = (now + TimeSpan.FromMinutes(2)).ToUnixTimeSeconds(),          // expires (2-min lifetime, max allowed is 5 min)
                ["jti"] = Guid.NewGuid().ToString("N"),                                 // unique ID — prevents replay attacks
            };

            string headerEncoded  = Base64UrlEncode(Encoding.UTF8.GetBytes(header.ToJsonString()));
            string payloadEncoded = Base64UrlEncode(Encoding.UTF8.GetBytes(payload.ToJsonString()));
            string signingInput   = $"{headerEncoded}.{payloadEncoded}";

            byte[] signature = rsa.SignData(
                Encoding.UTF8.GetBytes(signingInput),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            return $"{signingInput}.{Base64UrlEncode(signature)}";
        }

        /// <summary>
        /// Loads a certificate from the OS certificate store by thumbprint so its RSA private key
        /// can be passed to the OAuth constructor.
        /// <para>
        /// Platform notes:
        /// <list type="bullet">
        ///   <item><description>Windows — Windows Certificate Store; keys can be hardware-backed (TPM/HSM via CNG)</description></item>
        ///   <item><description>macOS — macOS Keychain (Cert:\CurrentUser\My maps to the login keychain)</description></item>
        ///   <item><description>Linux — protected PFX files in ~/.dotnet/corefx/cryptography/x509stores/my/</description></item>
        /// </list>
        /// </para>
        /// <para>
        /// The returned certificate must stay alive for as long as the RSA key is in use.
        /// Dispose both together:
        /// <code>
        /// using X509Certificate2 cert = BuzzApiClient.LoadCertificateFromStore(thumbprint);
        /// using RSA rsa = cert.GetRSAPrivateKey()!;
        /// var client = new BuzzApiClient(serverUrl, userAgent, userId, kid, rsa);
        /// </code>
        /// </para>
        /// </summary>
        /// <param name="thumbprint">The certificate thumbprint (hex string, spaces are ignored).</param>
        /// <param name="storeLocation">
        ///   <see cref="StoreLocation.CurrentUser"/> (default) for per-user installs and user-level services.
        ///   <see cref="StoreLocation.LocalMachine"/> for system-wide Windows services (requires admin to install).
        /// </param>
        public static X509Certificate2 LoadCertificateFromStore(
            string thumbprint,
            StoreLocation storeLocation = StoreLocation.CurrentUser)
        {
            using X509Store store = new(StoreName.My, storeLocation);
            store.Open(OpenFlags.ReadOnly);
            // Strip whitespace, colons, and any other non-hex characters so thumbprints
            // copied from OpenSSL output (e.g. "AB:CD:EF:...") work without manual editing.
            string normalizedThumbprint = new string(thumbprint.Where(
                c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')).ToArray());
            X509Certificate2Collection found = store.Certificates.Find(
                X509FindType.FindByThumbprint, normalizedThumbprint, validOnly: false);
            if (found.Count == 0)
                throw new InvalidOperationException(
                    $"Certificate with thumbprint '{thumbprint}' not found in the {storeLocation}/My store. " +
                    "Run the setup script to install it.");
            // Prefer the copy that has an accessible private key — the store can hold both
            // a public-only copy and a private-key copy with the same thumbprint.
            X509Certificate2? withKey = found.OfType<X509Certificate2>().FirstOrDefault(c => c.HasPrivateKey);
            if (withKey is null)
                throw new InvalidOperationException(
                    $"Certificate '{thumbprint}' was found in the {storeLocation}/My store but has no accessible private key. " +
                    "Re-run the setup script to reinstall it with the private key.");
            return withKey;
        }

        private static string Base64UrlEncode(byte[] data)
        {
            return Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        /// <summary>
        /// Reads the wait the server asked for: Retry-After (delta-seconds or HTTP date) first, then
        /// X-RateLimit-Reset, which Buzz sends as seconds until the rate-limit window resets (not a Unix time).
        /// The server sends these on throttled responses whether the HTTP status is 200 or 429/503.
        /// </summary>
        /// <returns>The server-directed wait, or null if the server gave none.</returns>
        private static TimeSpan? GetServerDirectedWait(HttpResponseHeaders headers)
        {
            RetryConditionHeaderValue? retryHeader = headers.RetryAfter;
            if (retryHeader?.Delta is TimeSpan delta && delta > TimeSpan.Zero)
                return delta;
            if (retryHeader?.Date is DateTimeOffset date && date > DateTimeOffset.UtcNow)
                return date - DateTimeOffset.UtcNow;
            if (int.TryParse(GetHeader(headers, "X-RateLimit-Reset"), out int resetSecs) && resetSecs > 0)
                return TimeSpan.FromSeconds(resetSecs);
            return null;
        }

        /// <summary>
        /// Computes how long to back off from a throttle: the server-directed wait if there is one (never less than the
        /// current exponential base), otherwise exponential backoff with jitter. A server-directed wait is not capped here;
        /// the caller compares it with <see cref="_maxServerDirectedWait"/> rather than retrying before the server said to.
        /// </summary>
        /// <returns>Duration to wait before retrying.</returns>
        private static TimeSpan GetThrottleWaitDuration(TimeSpan? serverWait, TimeSpan baseWaitDuration)
        {
            if (serverWait is TimeSpan wait)
                return wait > baseWaitDuration ? wait : baseWaitDuration;
            return TimeSpan.FromMilliseconds(Math.Min(_maxRetryWaitDuration.TotalMilliseconds, baseWaitDuration.TotalMilliseconds + Random.Shared.Next(1, 1000)));
        }

        /// <summary>
        /// The HTTP status to report for a throttle: the real one when the server sent 429/503, otherwise
        /// the status the envelope code stands for (the server wraps these in HTTP 200 for legacy clients).
        /// </summary>
        private static HttpStatusCode ThrottleStatusCode(HttpStatusCode statusCode, string? code)
        {
            if (statusCode == HttpStatusCode.TooManyRequests || statusCode == HttpStatusCode.ServiceUnavailable)
                return statusCode;
            return code is not null && s_overloadCodes.Contains(code)
                ? HttpStatusCode.ServiceUnavailable
                : HttpStatusCode.TooManyRequests;
        }

        private static bool IsThrottleCode(string? code) => code is not null && s_throttleCodes.Contains(code);

        /// <summary>
        /// Gets the envelope code, which is <c>response.code</c> for a normal response.
        /// </summary>
        private static string? GetResponseCode(JsonNode? envelope)
        {
            if (envelope is not JsonObject obj)
                return null;
            return (obj["response"] is JsonObject inner ? inner["code"] : obj["code"])?.ToString();
        }

        /// <summary>
        /// Gets the per-item results of a batch or multi-object command (<c>responses.response</c>).
        /// JSON always gives an array; a single item converted from XML is an object.
        /// </summary>
        private static List<JsonNode?> GetChildResponses(JsonNode? response)
        {
            JsonNode? items = response?["responses"]?["response"];
            if (items is JsonArray array)
                return array.ToList();
            return items is JsonObject ? new List<JsonNode?> { items } : new List<JsonNode?>();
        }

        /// <summary>
        /// Backs off the whole client when a successful batch or multi-object response contains throttled items,
        /// so resubmitting them (and any other requests sharing this client) waits as the server asked.
        /// </summary>
        private void ExtendThrottleWindowForThrottledItems(JsonNode? envelope, HttpResponseHeaders headers)
        {
            JsonNode? response = envelope is JsonObject obj && obj["response"] is JsonObject inner ? inner : envelope;
            int throttled = CountThrottledItems(response);
            if (throttled == 0)
                return;
            TimeSpan wait = GetThrottleWaitDuration(GetServerDirectedWait(headers), _initialWaitDuration);
            if (wait > _maxServerDirectedWait)
                wait = _maxServerDirectedWait;
            _logger?.LogWarning("{ThrottledCount} items in the response were throttled; backing off for {WaitTimeMs} milliseconds before the next request",
                throttled, (int)wait.TotalMilliseconds);
            ExtendThrottleWindow(wait);
        }

        /// <summary>
        /// Counts throttled items at any depth, since a batch item can itself be a multi-object command with per-row results.
        /// </summary>
        private static int CountThrottledItems(JsonNode? response)
            => GetChildResponses(response).Sum(item => (IsThrottleCode(item?["code"]?.ToString()) ? 1 : 0) + CountThrottledItems(item));

        /// <summary>
        /// Moves the client-wide throttle window out to at least <paramref name="wait"/> from now.
        /// </summary>
        private void ExtendThrottleWindow(TimeSpan wait)
        {
            long until = DateTime.UtcNow.Ticks + wait.Ticks;
            long current = Interlocked.Read(ref _throttledUntilTicks);
            while (until > current)
            {
                long previous = Interlocked.CompareExchange(ref _throttledUntilTicks, until, current);
                if (previous == current)
                    return;
                current = previous;
            }
        }

        /// <summary>
        /// Waits until the client-wide throttle window has passed.
        /// </summary>
        private async ValueTask WaitForThrottleWindow(CancellationToken cancel)
        {
            while (true)
            {
                long remainingTicks = Interlocked.Read(ref _throttledUntilTicks) - DateTime.UtcNow.Ticks;
                if (remainingTicks <= 0)
                    return;
                _logger?.LogDebug("Waiting {WaitTimeMs} milliseconds for the server's throttle window to pass", (int)TimeSpan.FromTicks(remainingTicks).TotalMilliseconds);
                await Task.Delay(TimeSpan.FromTicks(remainingTicks), cancel);
            }
        }

        private static string? GetHeader(HttpResponseHeaders headers, string name)
            => headers.TryGetValues(name, out IEnumerable<string>? values) ? values.FirstOrDefault() : null;

        /// <summary>
        /// Parses a response body as the XML or JSON envelope. The server returns XML unless JSON is requested,
        /// and some error paths may ignore the Accept header, so XML is converted to the equivalent JSON shape:
        /// attributes and child elements become properties, repeated elements become arrays, and text content becomes "$value".
        /// </summary>
        /// <returns>The envelope as JSON, or null for an empty body.</returns>
        private static JsonNode? ParseEnvelope(string body, string? mediaType)
        {
            if (string.IsNullOrWhiteSpace(body))
                return null;
            bool isXml = mediaType?.Contains("xml", StringComparison.OrdinalIgnoreCase) == true || body.TrimStart().StartsWith('<');
            if (!isXml)
                return JsonNode.Parse(body);
            XElement root = XDocument.Parse(body).Root ?? throw new FormatException("XML response has no root element.");
            return new JsonObject { [root.Name.LocalName] = XmlToJson(root) };
        }

        /// <summary>
        /// Like <see cref="ParseEnvelope"/>, but returns null instead of throwing when the body is not XML or JSON
        /// (for example, an HTML error page from a proxy).
        /// </summary>
        private static JsonNode? TryParseEnvelope(string body, string? mediaType)
        {
            try
            {
                return ParseEnvelope(body, mediaType);
            }
            catch (Exception e) when (IsParseException(e))
            {
                return null;
            }
        }

        private static bool IsParseException(Exception e) => e is System.Text.Json.JsonException or System.Xml.XmlException or FormatException;

        private static JsonObject XmlToJson(XElement element)
        {
            JsonObject obj = new();
            foreach (XAttribute attribute in element.Attributes().Where(a => !a.IsNamespaceDeclaration))
                obj[attribute.Name.LocalName] = attribute.Value;
            foreach (IGrouping<string, XElement> group in element.Elements().GroupBy(e => e.Name.LocalName))
            {
                List<XElement> children = group.ToList();
                obj[group.Key] = children.Count == 1
                    ? XmlToJson(children[0])
                    : new JsonArray(children.Select(c => (JsonNode?)XmlToJson(c)).ToArray());
            }
            string text = string.Concat(element.Nodes().OfType<XText>().Select(t => t.Value));
            if (!string.IsNullOrWhiteSpace(text))
                obj["$value"] = text;
            return obj;
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
                    actualMs = Math.Max(actualMs, Math.Max(0, (retryHeader.Date.Value - DateTime.UtcNow).TotalMilliseconds));
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
                    HttpStatusCode.NotFound or
                    HttpStatusCode.MethodNotAllowed or
                    HttpStatusCode.NotAcceptable or HttpStatusCode.ProxyAuthenticationRequired or
                    HttpStatusCode.Conflict or
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

        private void TraceRequest(string requestUri)
        {
            // Strip _token query parameter before logging — password-auth paths append it to the URI.
            // Body is never logged: request bodies contain credentials (password, MFA code, client_assertion).
            string redactedUri = RedactQueryParam(requestUri, "_token");
            if (Verbose)
                _logger?.LogInformation("Request: {RequestUri}", redactedUri);
            else
                _logger?.LogDebug("Request: {RequestUri}", redactedUri);
        }

        public void Dispose()
        {
            _httpClient.Dispose();
            _oauthTokenLock.Dispose();
        }

        private static string RedactQueryParam(string uri, string paramName)
        {
            int q = uri.IndexOf('?');
            if (q < 0) return uri;
            string[] kept = uri[(q + 1)..].Split('&')
                .Where(p => !p.StartsWith(paramName + "=", StringComparison.OrdinalIgnoreCase))
                .ToArray();
            return kept.Length > 0 ? $"{uri[..q]}?{string.Join("&", kept)}" : uri[..q];
        }

        private void TraceResponse(JsonNode? json)
        {
            if (_logger is null || !_logger.IsEnabled(LogLevel.Debug))
                return;
            if (json is not null)
            {
                string text = CloneAndRedact(json).ToString();
                _logger.LogDebug("Response: {Content}", text[..Math.Min(text.Length, 1000)]);
            }
            else
            {
                _logger.LogDebug("Response was empty or not json");
            }
        }

        private static readonly HashSet<string> s_sensitiveFields = new(StringComparer.OrdinalIgnoreCase)
            { "token", "access_token", "refresh_token", "password", "client_assertion", "client_secret" };

        private static JsonNode CloneAndRedact(JsonNode node)
        {
            if (node is JsonObject obj)
            {
                var result = new JsonObject();
                foreach (var (key, value) in obj)
                    result[key] = s_sensitiveFields.Contains(key) ? JsonValue.Create("[REDACTED]") : (value is null ? null : CloneAndRedact(value));
                return result;
            }
            if (node is JsonArray arr)
            {
                var result = new JsonArray();
                foreach (var item in arr)
                    result.Add(item is null ? null : CloneAndRedact(item));
                return result;
            }
            return node.DeepClone();
        }
    }
}
