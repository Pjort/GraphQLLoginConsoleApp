using GraphQL;
using GraphQL.Client.Http;
using GraphQL.Client.Serializer.Newtonsoft;
using GraphQLLoginConsoleApp.Models;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;

namespace GraphQLLoginConsoleApp
{
    class Program
    {

        private const string Endpoint = "https://auth.qualidrone.com";
        private static readonly HttpClient HttpClient = new HttpClient();
        private static readonly GraphQLHttpClient GraphQLClient = new GraphQLHttpClient(Endpoint + "/graphql", new NewtonsoftJsonSerializer());

        private const string ClientId = "6c702395-df28-4fc2-ad55-f344bbaa27e9";
        private const string PublicKeyPEM = @"
            -----BEGIN RSA PUBLIC KEY-----
            MIIBCgKCAQEA2TH2E8iXb75LsLludNuT/eiUSE5a2l7gGOKzUBMgcbmLJbZCrDp2
            ie6zjnz5M204hSzemKS6lJ55TThil/cx2KebCjDegzch839HYEz8ul/bnq3S5jYA
            bTJ8Xgv6792e88vw+b42i3Zqexz6RCFB63k8IUwnJXY9FG0ulNsdLo2ZuwbMs77o
            lMGMEkpuh7rpdJ1RAAyJVyFogrzQCghQsLeUzeksQBy+w/RJ0B5478fsIJ6Xgzs2
            EBQxf3Hnyr+eUDVaejZ4ijir6/wLlDX7+bU1e/WAuMxKUsgHk8ekCZraxJlaBCcs
            +Gtl39B/9T+esrRFxGiMrwToJ2Zcr3BSXwIDAQAB
            -----END RSA PUBLIC KEY-----
            ";

        static async Task Main(string[] args)
        {

            LoginData? loginData = await Login("ppk@qualidrone.com", "dU?Thq9N,B}7BM7");
            if (loginData == null)
            {
                Console.WriteLine("Login failed");
                return;
            }

            Console.WriteLine($"Access Token: {loginData.access_token}");
            Console.WriteLine($"Refresh Token: {loginData.refresh_token}");

            TimeSpan timeLeft = GetTokenTimeLeft(loginData.access_token);
            Console.WriteLine($"Access Token time left: {timeLeft}");

            loginData = await RefreshToken(loginData.refresh_token);
            if (loginData == null)
            {
                Console.WriteLine("Refresh token failed");
                return;
            }
            Console.WriteLine($"New Login Data access_token: {loginData.access_token}");
        }

        private static async Task<LoginData?> Login(string email, string password)
        {
            string mutation = @"
                mutation Login($email: String!, $password: String!) {
                    login(
                        params: {
                            email: $email
                            password: $password
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


            GraphQLHttpRequest request = new GraphQLHttpRequest
            {
                Query = mutation,
                Variables = new
                {
                    email,
                    password
                }
            };

            GraphQLResponse<LoginResponse> response = await GraphQLClient.SendQueryAsync<LoginResponse>(request);
            if (response.Errors != null)
            {
                return null;
            }
            LoginData? loginData = response.Data.login;
            return loginData;
        }

        private static TimeSpan GetTokenTimeLeft(string accessToken)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportFromPem(PublicKeyPEM);
            RsaSecurityKey securityKey = new RsaSecurityKey(rsa);

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            TokenValidationParameters validationParameters = new TokenValidationParameters
            {
                ValidIssuer = Endpoint,
                IssuerSigningKey = securityKey,
                ValidateIssuer = true,
                ValidateAudience = false,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            try
            {
                var claimsPrincipal = tokenHandler.ValidateToken(accessToken, validationParameters, out SecurityToken validatedToken);
                JwtSecurityToken? jwtSecurityToken = validatedToken as JwtSecurityToken;

                if (jwtSecurityToken == null)
                {
                    throw new Exception("Token validation failed.");
                }

                // Check for token type
                string? tokenType = jwtSecurityToken.Claims.FirstOrDefault(c => c.Type == "token_type")?.Value;

                if (string.IsNullOrEmpty(tokenType) || tokenType != "access_token")
                {
                    throw new Exception("Invalid or missing token type.");
                }

                DateTime expirationTime = jwtSecurityToken.ValidTo;
                return expirationTime - DateTime.UtcNow;
            }
            catch (Exception ex)
            {
                throw new Exception($"Token validation failed: {ex.Message}");
            }
        }

        private static async Task<LoginData?> RefreshToken(string refreshToken)
        {
            var requestData = new
            {
                grant_type = "refresh_token",
                client_id = ClientId,
                refresh_token = refreshToken
            };

            // Serialize the request data to JSON
            var jsonContent = JsonConvert.SerializeObject(requestData);
            var httpContent = new StringContent(jsonContent, Encoding.UTF8, "application/json");

            // Make the HTTP POST request
            var response = await HttpClient.PostAsync(Endpoint + "/oauth/token", httpContent);

            // Ensure the response is successful
            response.EnsureSuccessStatusCode();

            // Deserialize the response to LoginData
            LoginData? loginData = JsonConvert.DeserializeObject<LoginData>(await response.Content.ReadAsStringAsync());

            // Read and return the response content
            return loginData;
        }
    }
}