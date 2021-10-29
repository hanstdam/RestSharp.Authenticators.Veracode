using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace RestSharp.Authenticators.Veracode
{
    /// <summary>
    /// HMAC Authentication Header
    /// Based on Veracode C# HMAC code sample:
    /// https://help.veracode.com/r/c_hmac_signing_example_c_sharp
    /// Modified for portability.
    /// </summary>
    internal abstract class HmacAuthHeader
    {
        private static readonly RNGCryptoServiceProvider RngRandom = new();

        public static readonly HmacAuthHeader HmacSha256 = new HmacSha256AuthHeader();

        private HmacAuthHeader()
        {
        }

        protected abstract string GetHashAlgorithm();
        protected abstract string GetAuthorizationScheme();
        protected abstract string GetRequestVersion();
        protected abstract string GetTextEncoding();
        protected abstract int GetNonceSize();

        private static string CurrentDateStamp()
        {
            return ((long)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalMilliseconds).ToString();
        }

        private static byte[] NewNonce(int size)
        {
            var nonceBytes = new byte[size];
            RngRandom.GetBytes(nonceBytes);

            return nonceBytes;
        }

        private byte[] ComputeHash(byte[] data, byte[] key)
        {
            var mac = HMAC.Create(GetHashAlgorithm());
            if (mac == null)
            {
                return Array.Empty<byte>();
            }
            
            mac.Key = key;

            return mac.ComputeHash(data);
        }

        private byte[] CalculateDataSignature(byte[] apiKeyBytes, byte[] nonceBytes, string dateStamp, string data)
        {
            var kNonce = ComputeHash(nonceBytes, apiKeyBytes);
            var kDate = ComputeHash(Encoding.GetEncoding(GetTextEncoding()).GetBytes(dateStamp), kNonce);
            var kSignature = ComputeHash(Encoding.GetEncoding(GetTextEncoding()).GetBytes(GetRequestVersion()), kDate);

            return ComputeHash(Encoding.GetEncoding(GetTextEncoding()).GetBytes(data), kSignature);
        }

        public string CalculateAuthorizationHeader(string apiId, string apiKey, string hostName, string uriString, string urlQueryParams, string httpMethod)
        {
            if (urlQueryParams != null)
            {
                uriString += urlQueryParams;
            }
            
            var data = $"id={apiId}&host={hostName}&url={uriString}&method={httpMethod}";
            var dateStamp = CurrentDateStamp();
            var nonceBytes = NewNonce(GetNonceSize());
            var dataSignature = CalculateDataSignature(FromHexBinary(apiKey), nonceBytes, dateStamp, data);
            var authorizationParam = $"id={apiId},ts={dateStamp},nonce={ToHexBinary(nonceBytes)},sig={ToHexBinary(dataSignature)}";

            return GetAuthorizationScheme() + " " + authorizationParam;
        }

        private static string ToHexBinary(byte[] bytes)
        {
            var sb = new StringBuilder();
            foreach (var b in bytes)
            {
                sb.Append(b.ToString("X2"));
            }

            return sb.ToString();
        }

        private static byte[] FromHexBinary(string hexBinaryString)
        {
            var chars = hexBinaryString.ToCharArray();
            var buffer = new byte [chars.Length / 2 + chars.Length % 2];
            var charLength = chars.Length;

            if (charLength % 2 != 0) throw new ArgumentException("Invalid value for xsd:hexBinary");

            var bufIndex = 0;
            for (var i = 0; i < charLength - 1; i += 2)
            {
                buffer[bufIndex] = FromHex(chars[i]);
                buffer[bufIndex] <<= 4;
                buffer[bufIndex] += FromHex(chars[i + 1]);
                bufIndex++;
            }

            return buffer;
        }

        private static byte FromHex(char hexDigit)
        {
            try
            {
                return byte.Parse(hexDigit.ToString(), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            }
            catch (FormatException)
            {
                throw new ArgumentException("Invalid value for xsd:hexBinary");
            }
        }

        private sealed class HmacSha256AuthHeader : HmacAuthHeader
        {
            protected override string GetHashAlgorithm()
            {
                return "HmacSHA256";
            }

            protected override string GetAuthorizationScheme()
            {
                return "VERACODE-HMAC-SHA-256";
            }

            protected override string GetRequestVersion()
            {
                return "vcode_request_version_1";
            }

            protected override string GetTextEncoding()
            {
                return "UTF-8";
            }

            protected override int GetNonceSize()
            {
                return 16;
            }
        }
    }
}
