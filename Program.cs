using GraphQL.Client.Http;
using GraphQL.Client.Serializer.Newtonsoft;
using GraphQLLoginConsoleApp.Models;

namespace GraphQLLoginConsoleApp
{
    class Program
    {

        private const string Endpoint = "https://auth.qualidrone.com/graphql";

        static async Task Main(string[] args)
        {
            using var client = new GraphQLHttpClient(Endpoint, new NewtonsoftJsonSerializer());

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
            LoginData loginData = response.Data.login;

            Console.WriteLine($"Access Token: {loginData.access_token}");
        }
    }
}