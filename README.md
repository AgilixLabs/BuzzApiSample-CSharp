# BuzzApiSample-CSharp

A sample of how to call the Buzz API from C#. Feel free to use the BuzzApiClientSession in your C# code to help make API calls.

Setup
-----------
In order to run BuzzApiSample-CSharp you need to do the following:

1. Update the contactInformation variable to include your name, company name, company URL, email address, or other contact information. Combinations of those are okay, and are usually separated with ';'. For example, I could use:
```cs
string contactInformation = "+https://agilix.com/; paul.smith@agilix.com";
```

2. Update the applicationInformation variable to be the name of your application. If you're running the sample, you could use "BuzzAPISample", but if you use BuzzApiClient for something else you should change it to indicate your usage.
```cs
string applicationInformation = "BuzzAPISample";
```

3. Configure buzzServerUrl, userspace, username, and password for your Buzz environment. 
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
