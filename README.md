# BuzzApiSample-CSharp

A sample of how to call the Buzz API from C#. Feel free to use the BuzzApiClient in your C# code to help make API calls.

Overview
-----------
The Buzz API is an HTTP API, consisting of GET and POST requests. Most Buzz APIs
accept JSON or XML, and responses can also be in either JSON or XML. A typical 
workflow for a Buzz API consumer is to login and perform some actions.

BuzzApiSample:
1. Configures an instance of BuzzApiClient with a buzz server, and a signon user.
2. Determines the domain of the current user by calling GetUser2
3. Creates a new user in the same domain of the current user by calling CreateUsers
4. Gets the new user by calling GetUser2
5. Updates the new user by calling UpdateUsers
6. Gets the updated user by calling GetUser2
7. Deletes the new and updates user by calling DeleteUsers

BuzzApiClient makes calling the Buzz API simpler by:
- Managing the user session. BuzzApiClient automatically logs in when necessary, including
before making any requests, and if the session expires. A session can expire for a number of
reasons, including timing out, a password reset, or from another user terminating the session.
- Managing retries. In the rare case that a request fails unexpectedly, BuzzApiClient will
retry the request using exponential backoff plus a random value.
- Providing utility methods to make JSON requests and validate JSON responses.

Setup
-----------
In order to run BuzzApiSample-CSharp you need to do the following:

1. Update the contactInformation variable to include your name, company name, company URL, 
email address, or other contact information. Combinations of those are okay, and are usually 
separated with ';'. For example, I could use:
```cs
string contactInformation = "+https://agilix.com/; paul.smith@agilix.com";
```

2. Update the applicationInformation variable to be the name of your application. If you're 
running the sample, you could use "BuzzAPISample", but if you use BuzzApiClient for something 
else you should change it to indicate your usage.
```cs
string applicationInformation = "BuzzAPISample";
```

3. Configure buzzServerUrl, userspace, username, and password for your Buzz environment. The 
configured user should have rights to create, read, update, and delete users.
- buzzServerUrl is typically "https://api.agilixbuzz.com". 
- userspace is the userspace of the domain where the login user resides
- username and password are the username and password of the login user

For example:
```cs
string buzzServerUrl = "https://api.agilixbuzz.com";
string userspace = "userspacedoesnotexist";
string username = "adminuser";
string password = "xWv6V*uC9@7hm!";
```
