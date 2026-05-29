using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;

namespace BuzzAPISample
{
    class Program
    {
        static async Task Main()
        {
            /* CONFIGURATION
             *
             * Quickest path: run ./scripts/run-buzz-sample.sh (Linux/macOS) or
             * .\scripts\Run-BuzzSample.ps1 (Windows) — it checks whether setup has been done and runs it if not,
             * then launches this program.
             *
             * Manual path: create buzz-config.json yourself (see README.md) or run the
             * setup script directly.  buzz-config.json is always preferred over any
             * hardcoded values. */

            if (!File.Exists("buzz-config.json"))
                throw new FileNotFoundException(
                    "buzz-config.json not found.\n" +
                    "  Linux/macOS: ./scripts/run-buzz-sample.sh\n" +
                    "  Windows    : .\\scripts\\Run-BuzzSample.ps1\n" +
                    "  Manual     : see README.md");

            JsonNode fileCfg = JsonNode.Parse(File.ReadAllText("buzz-config.json"))
                ?? throw new InvalidOperationException("buzz-config.json is empty or does not contain a JSON object.");

            string serverUrl              = fileCfg["serverUrl"]?.ToString()              ?? throw new InvalidOperationException("'serverUrl' missing from buzz-config.json");
            string contactInformation     = fileCfg["contactInformation"]?.ToString()     ?? string.Empty;
            string applicationInformation = fileCfg["applicationInformation"]?.ToString() ?? string.Empty;
            string oauthUserId            = fileCfg["oauthUserId"]?.ToString()            ?? throw new InvalidOperationException("'oauthUserId' missing from buzz-config.json");
            string oauthKid               = fileCfg["oauthKid"]?.ToString()               ?? throw new InvalidOperationException("'oauthKid' missing from buzz-config.json");
            string? certThumbprint        = fileCfg["certThumbprint"]?.ToString();
            string? certStoreLocationStr  = fileCfg["certStoreLocation"]?.ToString();
            string? privateKeyPath        = fileCfg["privateKeyPath"]?.ToString();

            if (string.IsNullOrEmpty(certThumbprint) && string.IsNullOrEmpty(privateKeyPath))
                throw new InvalidOperationException(
                    "No private key source in buzz-config.json. " +
                    "Run the setup script or see README.md.");

            string userAgent = $"BuzzApiClient/1.0.0 (CSharp; {applicationInformation}; {contactInformation})";

            using ILoggerFactory loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
            ILogger<BuzzApiClient> logger = loggerFactory.CreateLogger<BuzzApiClient>();

            X509Certificate2? oauthCert = null;
            RSA? rsa = null;
            try
            {
                if (!string.IsNullOrEmpty(certThumbprint))
                {
                    StoreLocation storeLocation = string.Equals(certStoreLocationStr, "LocalMachine",
                        StringComparison.OrdinalIgnoreCase)
                        ? StoreLocation.LocalMachine
                        : StoreLocation.CurrentUser;

                    oauthCert = BuzzApiClient.LoadCertificateFromStore(certThumbprint, storeLocation);
                    rsa = oauthCert.GetRSAPrivateKey()
                        ?? throw new InvalidOperationException(
                            $"Certificate '{certThumbprint}' has no RSA private key.");
                }
                else
                {
                    rsa = RSA.Create();
                    rsa.ImportFromPem(File.ReadAllText(privateKeyPath!));
                }

                using BuzzApiClient client = new(serverUrl, userAgent, oauthUserId, oauthKid, rsa, verbose: false, logger: logger);

                await RunSample(client, logger);
            }
            finally
            {
                rsa?.Dispose();
                oauthCert?.Dispose();
            }
        }

        static async Task RunSample(BuzzApiClient client, ILogger<BuzzApiClient> logger)
        {
            Console.WriteLine();
            Console.WriteLine("════════════════════════════════════════════════════════");
            Console.WriteLine("  Buzz API OAuth 2.0 Sample — Read-Only Demo");
            Console.WriteLine("════════════════════════════════════════════════════════");
            Console.WriteLine();

            // ── GetUser2 ─────────────────────────────────────────────────────
            // Verify authentication is working and discover the domain this
            // Application Identity account belongs to.
            Console.WriteLine("── GetUser2 (verify authentication) ────────────────────");

            JsonNode userNode = client.VerifyResponse(
                await client.JsonRequest(HttpMethod.Get, "getuser2"));

            string? userId    = userNode["user"]?["userid"]?.ToString();
            string? username  = userNode["user"]?["username"]?.ToString();
            string? firstName = userNode["user"]?["firstname"]?.ToString();
            string? lastName  = userNode["user"]?["lastname"]?.ToString();
            string? domainId  = userNode["user"]?["domainid"]?.ToString();

            logger.LogInformation("Authenticated as user {Username} (\"{FirstName} {LastName}\", userid: {UserId})",
                username, firstName, lastName, userId);
            logger.LogInformation("Home domain: {DomainId}", domainId);

            // ── GetDomain2 ───────────────────────────────────────────────────
            // Fetch details about the domain the Application Identity account
            // belongs to, demonstrating a typical read API call.
            if (!string.IsNullOrEmpty(domainId))
            {
                Console.WriteLine();
                Console.WriteLine("── GetDomain2 (read domain details) ────────────────────");

                JsonNode domainNode = client.VerifyResponse(
                    await client.JsonRequest(HttpMethod.Get, "getdomain2", $"domainid={Uri.EscapeDataString(domainId)}"));

                string? domainName      = domainNode["domain"]?["name"]?.ToString();
                string? domainUserspace = domainNode["domain"]?["userspace"]?.ToString();
                string? domainType      = domainNode["domain"]?["type"]?.ToString();

                logger.LogInformation("Domain name: {Name}", domainName);
                logger.LogInformation("Userspace  : {Userspace}", domainUserspace);
                if (!string.IsNullOrEmpty(domainType))
                    logger.LogInformation("Type       : {Type}", domainType);
            }

            Console.WriteLine();
            Console.WriteLine("════════════════════════════════════════════════════════");
            Console.WriteLine("  All API calls succeeded.  OAuth integration is working.");
            Console.WriteLine("  No data was created or modified.");
            Console.WriteLine("════════════════════════════════════════════════════════");
            Console.WriteLine();
        }
    }
}
