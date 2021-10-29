namespace RestSharp.Authenticators.Veracode
{
    /// <summary>
    /// Veracode HMAC midleware for <see cref="IRestClient"/>.
    /// </summary>
    public class VeracodeAuthenticator : IAuthenticator
    {
        private readonly string _apiId;
        private readonly string _apiKey;
        private const string AuthorizationHeader = "Authorization";

        /// <summary>
        /// Creates a new instance of <see cref="VeracodeAuthenticator"/> class.
        /// </summary>
        /// <param name="apiId">The Veracode App Id.</param>
        /// <param name="apiKey">The Veracode App Key.</param>
        public VeracodeAuthenticator(string apiId, string apiKey)
        {
            _apiId = apiId;
            _apiKey = apiKey;
        }
        
        /// <inheritdoc cref="IAuthenticator" />.
        public void Authenticate(IRestClient client, IRestRequest request)
        {
            var uri = client.BuildUri(request);
            var authorization = HmacAuthHeader.HmacSha256.CalculateAuthorizationHeader(_apiId, _apiKey, uri.Host, uri.AbsolutePath, uri.Query, request.Method.ToString());

            request.AddHeader(AuthorizationHeader, authorization);
        }
    }
}