using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace CoreBB.Web.Controllers
{
    public class ErrorController : Controller
    {
        public IActionResult Index()
        {
            var exceptions = HttpContext.Features.Get<IExceptionHandlerFeature>();
            ViewData["StatusCode"] = HttpContext.Response.StatusCode;
            ViewData["Message"] = exceptions.Error.Message;
            ViewData["StackTrace"] = exceptions.Error.StackTrace;
            return View();
            //throw new Exception("Fake Error");
        }

        public IActionResult AccessDenied() => View();
    }
}