using System.Net;

namespace BuzzAPISample
{
    /// <summary>
    /// Thrown when Buzz refuses a request because it used something deprecated (response code "ApiDeprecated",
    /// or "unauthorized_client" from the OAuth token endpoint).
    /// <para>
    /// Deprecated commands, the api.agilixbuzz.com endpoint and password (Login3) sessions for integration work
    /// keep working for existing users and domains, but are refused for new ones. The message is the server's own
    /// and says what to use instead. Never retry: the request is refused until the code is changed.
    /// </para>
    /// <para>
    /// Derives from <see cref="HttpRequestException"/>, like <see cref="BuzzApiThrottledException"/>.
    /// <see cref="HttpRequestException.StatusCode"/> is the HTTP status of the OAuth token endpoint's refusal (400),
    /// and null when the refusal came in a response envelope, which the server sends with HTTP 200.
    /// </para>
    /// </summary>
    public class BuzzApiDeprecatedException : HttpRequestException
    {
        public BuzzApiDeprecatedException(string message, HttpStatusCode? statusCode = null)
            : base(message, null, statusCode)
        {
        }
    }
}
