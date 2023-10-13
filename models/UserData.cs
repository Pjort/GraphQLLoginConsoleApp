namespace GraphQLLoginConsoleApp.Models
{
    public class UserData
    {
        public string email { get; set; } = string.Empty;
        public List<string> roles { get; set; } = new List<string>();
    }
}