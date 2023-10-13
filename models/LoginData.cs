namespace GraphQLLoginConsoleApp.Models
{
    public class LoginData
    {
        public string access_token { get; set; } = string.Empty;
        public string refresh_token { get; set; } = string.Empty;
        public string message { get; set; } = string.Empty;
        public string id_token { get; set; } = string.Empty;
        public UserData user { get; set; } = new UserData();
        public int expires_in { get; set; }
    }
}