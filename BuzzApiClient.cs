using Microsoft.Extensions.Logging;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;

namespace BuzzAPISample
{
    /// <summary>
    /// Makes requests to a Buzz API server.
    /// Supports OAuth 2.0 JWT client credentials (RFC 6749 + RFC 7523) and legacy password-based login.
    /// </summary>
    public class BuzzApiClient
    {
        private const int _retriesToMake = 5;
        private static readonly TimeSpan _initialWaitDuration = TimeSpan.FromMilliseconds(1000);
        private static readonly TimeSpan _maxRetryWaitDuration = TimeSpan.FromMilliseconds(64000);

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

            serverUrl = serverUrl.TrimEnd('/');
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

            serverUrl = serverUrl.TrimEnd('/');
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

            serverUrl = serverUrl.TrimEnd('/');
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
            if (includeToken)
            {
                if (_oauthEnabled && (Token is null || DateTimeOffset.UtcNow >= _oauthTokenExpiry - _oauthTokenRefreshMargin))
                {
                    await AuthenticateOAuth(cancel);
                }
                else if (_autoLoginEnabled && Token is null)
                {
                    _logger?.LogInformation("Attempting to login");
                    await Login(cancel);
                }
            }

            using HttpContent? content = json is null ? null : new StringContent(json.ToJsonString(), Encoding.UTF8, "application/json");
            using HttpResponseMessage response = await RequestWithRetry(httpMethod, cmd, parameters, content, includeToken, cancel: cancel);
            JsonNode? responseNode = JsonNode.Parse(await response.Content.ReadAsStreamAsync(cancel));
            TraceResponse(responseNode);

            // If the token expired or was revoked, re-authenticate and retry the request once
            if (includeToken && Token is not null && responseNode?["response"]?["code"]?.ToString() == "NoAuthentication")
            {
                if (_oauthEnabled)
                {
                    _logger?.LogTrace("Re-authenticating via OAuth because the request returned code \"NoAuthentication\"");
                    await AuthenticateOAuth(cancel);
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
                using HttpResponseMessage retryResponse = await RequestWithRetry(httpMethod, cmd, parameters, content, includeToken, cancel: cancel);
                responseNode = JsonNode.Parse(await retryResponse.Content.ReadAsStreamAsync(cancel));
                TraceResponse(responseNode);
            }
            return responseNode;
        }

        private async ValueTask<HttpResponseMessage> RequestWithRetry(HttpMethod httpMethod, string? cmd, string? parameters, HttpContent? content,
            bool includeToken = true, string acceptsContentType = "application/json", CancellationToken cancel = default)
        {
            // OAuth uses Authorization: Bearer header; password auth uses _token query parameter
            if (!_oauthEnabled && includeToken && Token is not null)
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

                    await TraceRequestAsync(requestUri, content);

                    try
                    {
                        response = await _httpClient.SendAsync(httpRequestMessage, cancel);
                    }
                    finally
                    {
                        httpRequestMessage.Content = null; // detach shared content; caller owns its lifecycle
                    }
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
                catch
                {
                    // Non-retryable exception (or no retries left): dispose before propagating.
                    // No finally here — the success path returns response to the caller who is
                    // responsible for disposing it; a finally would dispose it prematurely.
                    response?.Dispose();
                    throw;
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

            string assertion = BuildClientAssertion(_oauthRsa!, _oauthUserId, _oauthKid, _oauthTokenEndpoint);

            using var formContent = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type",            "client_credentials"),
                new KeyValuePair<string, string>("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                new KeyValuePair<string, string>("client_assertion",      assertion),
            });

            using HttpResponseMessage response = await _httpClient.PostAsync(_oauthTokenEndpoint, formContent, cancel);

            if (!response.IsSuccessStatusCode)
            {
                string body = await response.Content.ReadAsStringAsync(cancel);
                _logger?.LogError("OAuth token request failed: {StatusCode} {Body}", response.StatusCode, body);
                throw new Exception($"OAuth token request failed ({response.StatusCode}): {body}");
            }

            JsonNode? tokenJson = JsonNode.Parse(await response.Content.ReadAsStreamAsync(cancel));
            string? accessToken = tokenJson?["access_token"]?.ToString();

            if (string.IsNullOrEmpty(accessToken))
            {
                throw new Exception($"OAuth token response did not contain an access_token: {tokenJson}");
            }

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
            Token = accessToken;
            _oauthTokenExpiry = DateTimeOffset.UtcNow.AddSeconds(expiresIn);

            _logger?.LogInformation("OAuth token obtained, expires in {ExpiresIn}s", expiresIn);
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
            X509Certificate2Collection found = store.Certificates.Find(
                X509FindType.FindByThumbprint, string.Concat(thumbprint.Split()), validOnly: false);
            if (found.Count == 0)
                throw new InvalidOperationException(
                    $"Certificate with thumbprint '{thumbprint}' not found in the {storeLocation}/My store. " +
                    "Run the setup script to install it.");
            return found[0];
        }

        private static string Base64UrlEncode(byte[] data)
        {
            return Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
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

        private async Task TraceRequestAsync(string requestUri, HttpContent? content)
        {
            _logger?.LogInformation("Request: {RequestUri}", requestUri);
            if (content is StringContent)
            {
                string text = await content.ReadAsStringAsync();
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
