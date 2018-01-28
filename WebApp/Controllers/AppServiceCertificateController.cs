using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace WebApp.Views
{
    [Authorize]
    public class AppServiceCertificateController : Controller
    {
        // GET: AppServiceCertificate
        public ActionResult Index()
        {
            return View();
        }
    }
}