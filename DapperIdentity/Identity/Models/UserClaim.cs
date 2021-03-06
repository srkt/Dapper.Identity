﻿using Dapper.Contrib.Extensions;


namespace Identity.Models
{
    [Table("AspNetUserClaims")]
     public class UserClaim
    {
        [Key]
        public int Id { get; set; }
        public string UserId { get; set; }
        public string ClaimType { get; set; }
        public string ClaimValue { get; set; }
    }
}
