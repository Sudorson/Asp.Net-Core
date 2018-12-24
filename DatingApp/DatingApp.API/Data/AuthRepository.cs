using System;
using System.Threading.Tasks;
using DatingApp.API.Models;
using Microsoft.EntityFrameworkCore;

namespace DatingApp.API.Data
{
    public class AuthRepository : IAuthRepository
    {
        private readonly DataContext _contex;
        public AuthRepository(DataContext contex)
        {
            _contex = contex;

        }
        public async Task<User> Login(string username, string password)
        {
            var user = await _contex.Users.FirstOrDefaultAsync(x => x.Username == username);
            if (user == null) 
            return null;

            if (!VerrifyPasswordHash(password, user.PasswordHash, user.PasswordSalt))
              return null;
            // Auth Successfull
            return user ;  
        }

        private bool VerrifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
             using( var hmac = new System.Security.Cryptography.HMACSHA512(passwordSalt))
          {

              var ComputedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
              for (int i = 0; i < ComputedHash.Length; i++)
              {
                  if (ComputedHash[i] != passwordHash[i]) return false;
                  
              }
          }
          return true;
        }

        public async Task<User> Register(User user, string password)
        {
            byte[] passwordHash, paswordSalt;
            CreatePasswordHash(password,out passwordHash,out paswordSalt);
            user.PasswordHash = passwordHash;
            user.PasswordSalt = paswordSalt;
            await _contex.Users.AddAsync(user);
            await _contex.SaveChangesAsync();
            return user;
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] paswordSalt)
        {
          using( var hmac = new System.Security.Cryptography.HMACSHA512())
          {
              paswordSalt = hmac.Key;
              passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
          }
        }

        public async Task<bool> UserExists(string username)
        {
            if (await _contex.Users.AnyAsync(x => x.Username == username)) return true;
            return false;
            
        }
    }
}
// iuhgiuhgui