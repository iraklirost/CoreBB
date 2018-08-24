using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using CoreBB.Web.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace CoreBB.Web.Controllers
{
    [Authorize]
    public class UserController : Controller
    {
        #region DBContext
        private CoreBBContext _dbContext;
        public UserController(CoreBBContext dbCotext)
        {
            _dbContext = dbCotext;
        }
        public IActionResult Index()
        {
            return View();
        }
        #endregion

        #region Registration Area
        [AllowAnonymous, HttpGet]
        public async Task<IActionResult> Register()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return View();
        }

        [AllowAnonymous, HttpPost]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid)
            {
                throw new Exception("Invalid registration information.");
            }

            model.Name = model.Name.Trim();
            model.Password = model.Password.Trim();
            model.RepeatPassword = model.RepeatPassword.Trim();

            var targetUser = _dbContext.User
                .SingleOrDefault(u => u.Name.Equals(model.Name, StringComparison.CurrentCultureIgnoreCase));

            if (targetUser != null)
            {
                throw new Exception("User name already exists.");
            }

            if (!model.Password.Equals(model.RepeatPassword))
            {
                throw new Exception("Passwords are not identical.");
            }

            var hasher = new PasswordHasher<User>();
            targetUser = new User { Name = model.Name, RegisterDateTime = DateTime.Now, Description = model.Description };
            targetUser.PasswordHash = hasher.HashPassword(targetUser, model.Password);

            if (_dbContext.User.Count() == 0)
            {
                targetUser.IsAdministrator = true;
            }

            await _dbContext.User.AddAsync(targetUser);
            await _dbContext.SaveChangesAsync();

            await LogInUserAsync(targetUser);

            return RedirectToAction("Index", "Home");
        }
        #endregion register

        #region Login User Area
        private async Task LogInUserAsync(User user)
        {
            var claims = new List<Claim>();
            claims.Add(new Claim(ClaimTypes.Name, user.Name));
            if (user.IsAdministrator)
            {
                claims.Add(new Claim(ClaimTypes.Role, Roles.Administrator));
            }

            var claimsIndentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var claimsPrincipal = new ClaimsPrincipal(claimsIndentity);
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, claimsPrincipal);
            user.LastLogInDateTime = DateTime.Now;
            await _dbContext.SaveChangesAsync();
        }
        #endregion

        #region Login Checker
        [AllowAnonymous, HttpPost]
        public async Task<IActionResult> LogIn(LogInViewModel model)
        {
            if (!ModelState.IsValid)
            {
                throw new Exception("Invalid user information.");
            }

            var targetUser = _dbContext.User.SingleOrDefault(u => u.Name.Equals(model.Name, StringComparison.CurrentCultureIgnoreCase));
            if (targetUser == null)
            {
                throw new Exception("User does not exist.");
            }

            var hasher = new PasswordHasher<User>();
            var result = hasher.VerifyHashedPassword(targetUser, targetUser.PasswordHash, model.Password);
            if (result != PasswordVerificationResult.Success)
            {
                throw new Exception("The password is wrong.");
            }

            await LogInUserAsync(targetUser);
            return RedirectToAction("Index", "Home");
        }
        #endregion
       
        #region Logout
        [HttpGet]
        public async Task<IActionResult> LogOut()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Index", "Home");
        }
        #endregion

        #region Login View(Get)
        [AllowAnonymous, HttpGet]
        public async Task<IActionResult> LogIn()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return View();
        }
        #endregion

        #region Details
        [HttpGet]
        public IActionResult Details(string name)
        {

            var user = _dbContext.User.SingleOrDefault(u => u.Name == name);
            if (user == null)
                throw new Exception("User name already exists");

            return View(user);
        }
        #endregion
    }
}