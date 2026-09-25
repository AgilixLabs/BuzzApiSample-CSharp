using System.Net;
using System.Text.Json.Nodes;

namespace BuzzAPISample
{
    /// <summary>
    /// Thrown when the Buzz API throttles a request (rate limit, time limit, or backend pressure) and the client
    /// has run out of retries, or when items within a batch or multi-object request were throttled.
    /// <para>
    /// Derives from <see cref="HttpRequestException"/> so existing handlers for HTTP 429/503 still catch it.
    /// <see cref="HttpRequestException.StatusCode"/> is 429 or 503 even when the server wrapped the throttle in HTTP 200.
    /// </para>
    /// </summary>
    public class BuzzApiThrottledException : HttpRequestException
    {
        /// <summary>
        /// The throttle code from the response envelope (for example "TimeLimit", "RateLimit", "BackendPressure",
        /// or "TooManyRequests"), or the OAuth error code for the token endpoint. Null if the server sent no code.
        /// </summary>
        public string? Code { get; }

        /// <summary>
        /// How long the server asked the client to wait (Retry-After or X-RateLimit-Reset), if it said.
        /// </summary>
        public TimeSpan? RetryAfter { get; }

        /// <summary>
        /// For batch and multi-object requests, the indexes of the items that were throttled and should be resubmitted.
        /// Items not listed here completed normally (or failed for other reasons) and should not be resubmitted.
        /// Empty when the whole request was throttled.
        /// </summary>
        public IReadOnlyList<int> ThrottledItemIndexes { get; }

        /// <summary>
        /// The full response envelope, including the results of any items that were not throttled.
        /// </summary>
        public JsonNode? Response { get; }

        public BuzzApiThrottledException(string message, string? code, JsonNode? response, IReadOnlyList<int> throttledItemIndexes,
            TimeSpan? retryAfter = null, HttpStatusCode statusCode = HttpStatusCode.TooManyRequests)
            : base(message, null, statusCode)
        {
            Code = code;
            Response = response;
            ThrottledItemIndexes = throttledItemIndexes;
            RetryAfter = retryAfter;
        }
    }
}
