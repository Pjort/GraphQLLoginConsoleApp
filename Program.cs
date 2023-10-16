using GraphQL;
using GraphQL.Client.Http;
using GraphQL.Client.Serializer.Newtonsoft;
using GraphQLLoginConsoleApp.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;

namespace GraphQLLoginConsoleApp
{
    class Program
    {

        private const string Endpoint = "https://auth.qualidrone.com";

        private const string publicKeyPEM = @"
            -----BEGIN PUBLIC KEY-----
            2TH2E8iXb75LsLludNuT_eiUSE5a2l7gGOKzUBMgcbmLJbZCrDp2ie6zjnz5M204hSzemKS6lJ55TThil_cx2KebCjDegzch839HYEz8ul_bnq3S5jYAbTJ8Xgv6792e88vw-b42i3Zqexz6RCFB63k8IUwnJXY9FG0ulNsdLo2ZuwbMs77olMGMEkpuh7rpdJ1RAAyJVyFogrzQCghQsLeUzeksQBy-w_RJ0B5478fsIJ6Xgzs2EBQxf3Hnyr-eUDVaejZ4ijir6_wLlDX7-bU1e_WAuMxKUsgHk8ekCZraxJlaBCcs-Gtl39B_9T-esrRFxGiMrwToJ2Zcr3BSXw
            -----END PUBLIC KEY-----
            ";

        private const string e = "AQAB";
        private const string n = "2TH2E8iXb75LsLludNuT_eiUSE5a2l7gGOKzUBMgcbmLJbZCrDp2ie6zjnz5M204hSzemKS6lJ55TThil_cx2KebCjDegzch839HYEz8ul_bnq3S5jYAbTJ8Xgv6792e88vw-b42i3Zqexz6RCFB63k8IUwnJXY9FG0ulNsdLo2ZuwbMs77olMGMEkpuh7rpdJ1RAAyJVyFogrzQCghQsLeUzeksQBy-w_RJ0B5478fsIJ6Xgzs2EBQxf3Hnyr-eUDVaejZ4ijir6_wLlDX7-bU1e_WAuMxKUsgHk8ekCZraxJlaBCcs-Gtl39B_9T-esrRFxGiMrwToJ2Zcr3BSXw";

        static async Task Main(string[] args)
        {
            using var client = new GraphQLHttpClient(Endpoint + "/graphql", new NewtonsoftJsonSerializer());

            GraphQLResponse<LoginResponse> response = await Login(client);
            LoginData loginData = response.Data.login;

            Console.WriteLine($"Access Token: {loginData.access_token}");

            // The provided exponent in base64url encoding
            var rsa = RSA.Create();
            rsa.ImportParameters(
                new RSAParameters
                {
                    Modulus = Base64UrlDecode(n),
                    Exponent = Base64UrlDecode(e)
                });

            var rsaSecurityKey = new RsaSecurityKey(rsa);

            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                ValidIssuer = "https://auth.qualidrone.com",
                IssuerSigningKey = rsaSecurityKey,
                ValidateIssuer = true,
                ValidateAudience = false,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            try
            {
                var claimsPrincipal = tokenHandler.ValidateToken(loginData.access_token, validationParameters, out SecurityToken validatedToken);
                JwtSecurityToken? jwtSecurityToken = validatedToken as JwtSecurityToken;
                if (jwtSecurityToken == null)
                {
                    Console.WriteLine("Token validation failed");
                    return;
                }
                else
                {
                    DateTime expirationTime = jwtSecurityToken.ValidTo;
                    TimeSpan timeLeft = expirationTime - DateTime.UtcNow;
                    Console.WriteLine($"Token will expire at {expirationTime}. Time left: {timeLeft}");
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Token validation failed: {ex.Message}");
            }
        }

        private static async Task<GraphQLResponse<LoginResponse>> Login(GraphQLHttpClient client)
        {
            var mutation = @"
                mutation {
                    login(
                        params: {
                            email: ""ppk@qualidrone.com""
                            password: ""dU?Thq9N,B}7BM7""
                            scope: ""offline_access""
                        }
                    ) {
                        access_token
                        refresh_token
                        message
                        id_token
                        user {
                            email
                            roles
                        }
                        expires_in
                    }
                }";

            var request = new GraphQLHttpRequest
            {
                Query = mutation
            };

            var response = await client.SendQueryAsync<LoginResponse>(request);
            return response;
        }

        public static byte[] Base64UrlDecode(string base64Url)
        {
            string padded = base64Url.Length % 4 == 0
                ? base64Url : base64Url + "====".Substring(base64Url.Length % 4);
            string base64 = padded.Replace("_", "/").Replace("-", "+");
            return Convert.FromBase64String(base64);
        }
    }
}