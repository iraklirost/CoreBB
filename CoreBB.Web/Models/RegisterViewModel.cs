using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace CoreBB.Web.Models
{
    public class RegisterViewModel
    {
        [Required,Display(Name= "Name")]
        public string Name { get; set; }

        [Required, Display(Name = "Password")]
        public string Password { get; set; }

        [Required, Display(Name = "Repeat Password")]
        public string RepeatPassword { get; set; }

        [Required, Display(Name = "Self-Introduction")]
        public string Description { get; set; }
    }
}
