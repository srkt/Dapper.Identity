
using Dapper.Contrib.Extensions;

namespace Identity.Models
{
    [Table("AspNetUserLogins")]
    public class UserLogin
    {
        [Key]
        public string LoginProvider { get; set; }
        [Key]
        public string ProviderKey { get; set; }
        [Key]
        public string UserId { get; set; }
    }
}
