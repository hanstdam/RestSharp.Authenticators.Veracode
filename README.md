# RestSharp.Authenticators.Veracode

RestSharp Authenticator for Veracode HMAC based API authentication

Description of HMAC Authentication with Veracode APIs is available here: https://help.veracode.com/r/c_enabling_hmac

## Prerequisites
Install Restsharp nuget package
```
Install-Package RestSharp
```

Install Contrib.RestSharp.Authenticators.Veracode nuget package
```
Install-Package Contrib.RestSharp.Authenticators.Veracode
```

## Example Veracode Rest API
```c#
using RestSharp;
using RestSharp.Authenticators.Veracode;

namespace RestSharp.Authenticators.Veracode.Examples.Rest
{
    class Program
    {
        // DO NOT HARDCODE YOUR CREDENTIALS!
        private const string ApiId = "xxx";
        private const string ApiKey = "yyy";

        static void Main(string[] args)
        {
            var client = new RestClient("https://api.veracode.com");
            client.Authenticator = new VeracodeAuthenticator(ApiId, ApiKey);
            var request = new RestRequest("/appsec/v1/applications", Method.GET);
            request.AddParameter("scan_type", "STATIC", ParameterType.QueryString);

            var response = client.Execute(request);
        }
    }
}
```

## Example Veracode XML API
```c#
using RestSharp;
using RestSharp.Authenticators.Veracode;

namespace RestSharp.Authenticators.Veracode.Examples.Xml
{
    class Program
    {
        // DO NOT HARDCODE YOUR CREDENTIALS!
        private const string ApiId = "xxx";
        private const string ApiKey = "yyy";

        static void Main(string[] args)
        {
            var client = new RestClient("https://analysiscenter.veracode.com/api/5.0");
            client.Authenticator = new VeracodeAuthenticator(ApiId, ApiKey);
            var request = new RestRequest("getbuildlist.do", Method.GET);
            request.AddParameter("app_id", "11111111", ParameterType.QueryString);

            var response = client.Execute(request);
        }
    }
}
```