using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using System.Data.Common;
using Identity.Models;
using Identity.Repository;

namespace Identity.Stores
{
    public class UserStore<TUser, TRole> : IUserLoginStore<TUser>,
        IUserClaimStore<TUser>,
        IUserRoleStore<TUser>,
        IUserPasswordStore<TUser>,
        IUserSecurityStampStore<TUser>,        
        IUserEmailStore<TUser>,
        IUserPhoneNumberStore<TUser>,
        IUserTwoFactorStore<TUser, string>,
        IUserLockoutStore<TUser, string>,
        IUserStore<TUser>
        where TUser : class, IDapperIdentity<TUser>
        where TRole : IRole 

    {
        private readonly UserTable<TUser> _userTable;
        private readonly RoleTable<TRole> _roleTable;
        private readonly UserRolesTable<TUser> _userRolesTable;
        private readonly UserClaimsTable<TUser> _userClaimsTable;
        private readonly UserLoginsTable<TUser> _userLoginsTable;
        public DbConnection Database { get; private set; }

        public UserStore(DbConnection database)
        {
            Database = database;
            _userTable = new UserTable<TUser>(database);
            _roleTable = new RoleTable<TRole>(database);
            _userRolesTable = new UserRolesTable<TUser>(database);
            _userClaimsTable = new UserClaimsTable<TUser>(database);
            _userLoginsTable = new UserLoginsTable<TUser>(database);
        }

        public IEnumerable<TUser> Users()
        {
            return _userTable.Users();
        }


        public Task AddClaimAsync(TUser user, Claim claim)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            if (claim == null)
            {
                throw new ArgumentNullException("user");
            }

            _userClaimsTable.Insert(user, claim);

            return Task.FromResult<object>(null);
        }

        public Task AddLoginAsync(TUser user, UserLoginInfo login)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            if (login == null)
            {
                throw new ArgumentNullException("login");
            }

            _userLoginsTable.Insert(user, login);

            return Task.FromResult<object>(null);
        }

        public Task AddToRoleAsync(TUser user, string roleName)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            if (string.IsNullOrEmpty(roleName))
            {
                throw new ArgumentException("Argument cannot be null or empty: roleName.");
            }

            var identRole = _roleTable.GetRoleByName(roleName);
            if (!string.IsNullOrEmpty(identRole.Id))
            {
                _userRolesTable.Insert(user, identRole.Id);
            }

            return Task.FromResult<object>(null);
        }

        public Task CreateAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            _userTable.Insert(user);

            return Task.FromResult<object>(null);
        }

        public Task DeleteAsync(TUser user)
        {
            if (user != null)
            {
                _userTable.Delete(user);
            }

            return Task.FromResult<Object>(null);
        }

        public Task<TUser> FindAsync(UserLoginInfo login)
        {
            if (login == null)
            {
                throw new ArgumentNullException("login");
            }

            var userId = _userLoginsTable.FindUserIdbyLogin(login);
            if (userId != null)
            {
                TUser user = _userTable.GetUserById(userId) as TUser;
                if (user != null)
                {
                    return Task.FromResult<TUser>(user);
                }
            }

            return Task.FromResult<TUser>(null);
        }

        public Task<TUser> FindByEmailAsync(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
            {
                throw new ArgumentException("Null or empty argument: email");
            }

            TUser user = _userTable.GetUserByEmail(email);
            return Task.FromResult<TUser>(user);
        }

        public Task<TUser> FindByIdAsync(string userId)
        {
            if (string.IsNullOrEmpty(userId))
            {
                throw new ArgumentException("Null or empty argument: userId");
            }

            TUser result = _userTable.GetUserById(userId) as TUser;
            if (result != null)
            {
                return Task.FromResult<TUser>(result);
            }

            return Task.FromResult<TUser>(null);
        }

        public Task<TUser> FindByNameAsync(string userName)
        {
            if (string.IsNullOrEmpty(userName))
            {
                throw new ArgumentException("Null or empty argument: userName");
            }

            var result = _userTable.GetUserByName(userName);

            return Task.FromResult<TUser>(result);
        }

        public Task<int> GetAccessFailedCountAsync(TUser user)
        {
            return Task.FromResult(user.AccessFailedCount);
        }

        public Task<IList<Claim>> GetClaimsAsync(TUser user)
        {
            var claims = _userClaimsTable.FindByUserId(user.Id);

            return Task.FromResult<IList<Claim>>(claims);
        }

        public Task<string> GetEmailAsync(TUser user)
        {
            return Task.FromResult(user.Email);
        }

        public Task<bool> GetEmailConfirmedAsync(TUser user)
        {
            return Task.FromResult(user.EmailConfirmed);
        }

        public Task<bool> GetLockoutEnabledAsync(TUser user)
        {
            return Task.FromResult(user.LockoutEnabled);
        }

        public Task<DateTimeOffset> GetLockoutEndDateAsync(TUser user)
        {
            return Task.FromResult(user.LockoutEndDateUtc.HasValue
                              ? new DateTimeOffset(DateTime.SpecifyKind(user.LockoutEndDateUtc.Value, DateTimeKind.Utc))
                              : new DateTimeOffset());
        }

        public Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user)
        {            
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            List<UserLoginInfo> logins = _userLoginsTable.FindAllByUserId(user.Id);
            if (logins != null)
            {
                return Task.FromResult<IList<UserLoginInfo>>(logins);
            }

            return Task.FromResult<IList<UserLoginInfo>>(null);
        }

        public Task<string> GetPasswordHashAsync(TUser user)
        {
            string passwordHash = _userTable.GetPasswordHash(user.Id);

            return Task.FromResult<string>(passwordHash);
        }

        public Task<string> GetPhoneNumberAsync(TUser user)
        {
            return Task.FromResult(user.PhoneNumber);
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(TUser user)
        {
            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        public Task<IList<string>> GetRolesAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            List<string> roles = _userRolesTable.FindByUserId(user.Id);
            {
                if (roles != null)
                {
                    return Task.FromResult<IList<string>>(roles);
                }
            }

            return Task.FromResult<IList<string>>(null);
        }

        public Task<string> GetSecurityStampAsync(TUser user)
        {
            return Task.FromResult(user.SecurityStamp);
        }

        public Task<bool> GetTwoFactorEnabledAsync(TUser user)
        {
            return Task.FromResult(user.TwoFactorEnabled);
        }

        public Task<bool> HasPasswordAsync(TUser user)
        {
            var hasPassword = !string.IsNullOrEmpty(_userTable.GetPasswordHash(user.Id));

            return Task.FromResult<bool>(Boolean.Parse(hasPassword.ToString()));
        }

        public Task<int> IncrementAccessFailedCountAsync(TUser user)
        {
            user.AccessFailedCount++;
            _userTable.Update(user);

            return Task.FromResult<int>(user.AccessFailedCount);
        }

        public Task<bool> IsInRoleAsync(TUser user, string roleName)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            if (string.IsNullOrEmpty(roleName))
            {
                throw new ArgumentNullException("role");
            }

            List<string> roles = _userRolesTable.FindByUserId(user.Id);
            {
                if (roles != null && roles.Contains(roleName))
                {
                    return Task.FromResult<bool>(true);
                }
            }

            return Task.FromResult<bool>(false);
        }

        public Task RemoveClaimAsync(TUser user, Claim claim)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            if (claim == null)
            {
                throw new ArgumentNullException("claim");
            }

            _userClaimsTable.DeleteSingleclaim(user, claim);

            return Task.FromResult<object>(null);
        }

        public Task RemoveFromRoleAsync(TUser user, string roleName)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            if (string.IsNullOrWhiteSpace(roleName))
            {
                throw new ArgumentNullException("roleName");
            }

            _userRolesTable.RemoveUserFromRole(user, roleName);
            return Task.FromResult<object>(null);
        }

        public Task RemoveLoginAsync(TUser user, UserLoginInfo login)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            if (login == null)
            {
                throw new ArgumentNullException("login");
            }

            _userLoginsTable.Delete(user, login);

            return Task.FromResult<Object>(null);
        }

        public Task ResetAccessFailedCountAsync(TUser user)
        {
            user.AccessFailedCount = 0;
            _userTable.Update(user);

            return Task.FromResult(0);
        }

        public Task SetEmailAsync(TUser user, string email)
        {
            user.Email = email;
            _userTable.Update(user);

            return Task.FromResult(0);
        }

        public Task SetEmailConfirmedAsync(TUser user, bool confirmed)
        {
            user.EmailConfirmed = confirmed;
            _userTable.Update(user);

            return Task.FromResult(0);
        }

        public Task SetLockoutEnabledAsync(TUser user, bool enabled)
        {
            user.LockoutEnabled = enabled;
            _userTable.Update(user);

            return Task.FromResult(0);
        }

        public Task SetLockoutEndDateAsync(TUser user, DateTimeOffset lockoutEnd)
        {
            user.LockoutEndDateUtc = lockoutEnd.UtcDateTime;
            _userTable.Update(user);

            return Task.FromResult(0);
        }

        public Task SetPasswordHashAsync(TUser user, string passwordHash)
        {
            user.PasswordHash = passwordHash;
            _userTable.Update(user);
            return Task.FromResult<Object>(null);
        }

        public Task SetPhoneNumberAsync(TUser user, string phoneNumber)
        {
            user.PhoneNumber = phoneNumber;
            _userTable.Update(user);

            return Task.FromResult(0);
        }

        public Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed)
        {
            user.PhoneNumberConfirmed = confirmed;
            _userTable.Update(user);

            return Task.FromResult(0);
        }

        public Task SetSecurityStampAsync(TUser user, string stamp)
        {
            user.SecurityStamp = stamp;
            _userTable.Update(user);
            return Task.FromResult(0);
        }

        public Task SetTwoFactorEnabledAsync(TUser user, bool enabled)
        {
            user.TwoFactorEnabled = enabled;
            _userTable.Update(user);

            return Task.FromResult(0);
        }

        public Task UpdateAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            _userTable.Update(user);

            return Task.FromResult<object>(null);
        }


        public void Dispose()
        {
            if (Database != null)
            {
                Database.Dispose();
                Database = null;
            }
        }

    }
}
