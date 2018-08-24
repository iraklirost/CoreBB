using System;
using System.Collections.Generic;

namespace CoreBB.Web.Models
{
    public partial class Message
    {
        public int Id { get; set; }
        public int FromUserId { get; set; }
        public int ToUserId { get; set; }
        public DateTime SendDateTime { get; set; }
        public bool IsRead { get; set; }
        public string Title { get; set; }
        public string Content { get; set; }

        public User FromUser { get; set; }
        public User ToUser { get; set; }
    }
}
