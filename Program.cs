﻿
using System.Text.Json.Nodes;

namespace BuzzAPISample
{
    class Program
    {
        static async Task Main()
        {
            /* BEFORE RUNNING
             * 1. Set contactInformation to your name, company name, company URL, email address, or other contact information.
             *    Combinations of those are okay, and are usually separated with ';'
             *    For example, I could use:
             *      string contactInformation = "+https://agilix.com/; paul.smith@agilix.com";
             * 2. Set applicationInformation to the name of your application.
             *    If you're running the sample, you could use "BuzzAPISample"
             *      string applicationInformation = "BuzzAPISample";
             * 3. Configure buzzServerUrl, userspace, username, and password for your Buzz environment.
             *    buzzServerUrl is typically "https://api.agilixbuzz.com"
             *    userspace is the userspace of the domain where the login user resides
             *    username and password are the username and password of the login user
             */

            string contactInformation = ;
            string applicationInformation = ;
            string userAgent = $"BuzzApiClient/1.0.0 (CSharp; {applicationInformation}; {contactInformation})";

            // Update these for your environment. Contact Agilix support if you need help.
            string buzzServerUrl = ;
            string userspace = ;
            string username = ;
            string password = ;

            // Create the BuzzApiClient
            BuzzApiClient client = new(buzzServerUrl, userAgent, userspace, username, password, verbose: true);

            // Get the signed on user (login automatically)
            JsonNode getUserResponse = BuzzApiClient.VerifyResponse(await client.JsonRequest(HttpMethod.Get, "getuser2"));
            string? domainId = getUserResponse["user"]?["domainid"]?.ToString();

            // Create a user
            JsonNode createUserResponse = BuzzApiClient.VerifyResponse(
                await client.JsonRequest(HttpMethod.Post, "createusers",
                    json: new JsonObject
                    {
                        ["requests"] = new JsonObject
                        {
                            ["user"] = new JsonArray
                            {
                                new JsonObject
                                {
                                    ["username"] = "testuser",
                                    ["password"] = "password",
                                    ["firstname"] = "Test",
                                    ["lastname"] = "User",
                                    ["domainid"] = domainId
                                }
                            }
                        }
                    }));

            // Get the new user's ID
            string? newUserId = createUserResponse["responses"]?["response"]?[0]?["user"]?["userid"]?.ToString();
            _ = newUserId ?? throw new Exception($"Unable to get the new user's ID at responses.response[0].user.userid from: {createUserResponse}");
            Console.WriteLine($"newUserId: {newUserId}");

            // Call GetUser2 with the user ID
            BuzzApiClient.VerifyResponse(await client.JsonRequest(HttpMethod.Get, "getuser2", $"userid={newUserId}"));

            // Update the user to have an email address
            BuzzApiClient.VerifyResponse(
                await client.JsonRequest(HttpMethod.Post, "updateusers", json:
                    new JsonObject
                    {
                        ["requests"] = new JsonObject
                        {
                            ["user"] = new JsonArray
                            {
                                new JsonObject
                                {
                                    ["userid"] = newUserId,
                                    ["email"] = "myemail@school.edu"
                                }
                            }
                        }
                    }));

            // Call GetUser2 to see the user with the email address
            BuzzApiClient.VerifyResponse(await client.JsonRequest(HttpMethod.Get, "getuser2", $"userid={newUserId}"));

            // Delete the user
            BuzzApiClient.VerifyResponse(
                await client.JsonRequest(HttpMethod.Post, "deleteusers", json:
                    new JsonObject
                    {
                        ["requests"] = new JsonObject
                        {
                            ["user"] = new JsonArray
                            {
                                new JsonObject
                                {
                                    ["userid"] = newUserId
                                }
                            }
                        }
                    }));
        }
    }
}