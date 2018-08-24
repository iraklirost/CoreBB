using System;
using System.IO;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.Extensions.Configuration;

namespace CoreBB.Web.Models
{
    public partial class CoreBBContext : DbContext
    {
        public CoreBBContext()
        {
        }

        public CoreBBContext(DbContextOptions<CoreBBContext> options)
            : base(options)
        {
        }

        public virtual DbSet<Forum> Forum { get; set; }
        public virtual DbSet<Message> Message { get; set; }
        public virtual DbSet<Topic> Topic { get; set; }
        public virtual DbSet<User> User { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json");
                var configuration = builder.Build();
                optionsBuilder.UseSqlServer(configuration.GetConnectionString("DefaultConnection"));
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Forum>(entity =>
            {
                entity.Property(e => e.Id).HasColumnName("ID");

                entity.Property(e => e.Description).HasMaxLength(1000);

                entity.Property(e => e.Name)
                    .IsRequired()
                    .HasMaxLength(50);

                entity.Property(e => e.OwnerId).HasColumnName("OwnerID");

                entity.HasOne(d => d.Owner)
                    .WithMany(p => p.Forum)
                    .HasForeignKey(d => d.OwnerId)
                    .OnDelete(DeleteBehavior.ClientSetNull)
                    .HasConstraintName("FK_Forum_Owner");
            });

            modelBuilder.Entity<Message>(entity =>
            {
                entity.Property(e => e.Id).HasColumnName("ID");

                entity.Property(e => e.Content)
                    .IsRequired()
                    .HasMaxLength(1000);

                entity.Property(e => e.FromUserId).HasColumnName("FromUserID");

                entity.Property(e => e.Title)
                    .IsRequired()
                    .HasMaxLength(50);

                entity.Property(e => e.ToUserId).HasColumnName("ToUserID");

                entity.HasOne(d => d.FromUser)
                    .WithMany(p => p.MessageFromUser)
                    .HasForeignKey(d => d.FromUserId)
                    .OnDelete(DeleteBehavior.ClientSetNull)
                    .HasConstraintName("FK_Message_FromUser");

                entity.HasOne(d => d.ToUser)
                    .WithMany(p => p.MessageToUser)
                    .HasForeignKey(d => d.ToUserId)
                    .OnDelete(DeleteBehavior.ClientSetNull)
                    .HasConstraintName("FK_Message_ToUser");
            });

            modelBuilder.Entity<Topic>(entity =>
            {
                entity.Property(e => e.Id).HasColumnName("ID");

                entity.Property(e => e.Content)
                    .IsRequired()
                    .HasMaxLength(1000);

                entity.Property(e => e.ForumId).HasColumnName("ForumID");

                entity.Property(e => e.ModifiedByUserId).HasColumnName("ModifiedByUserID");

                entity.Property(e => e.OwnerId).HasColumnName("OwnerID");

                entity.Property(e => e.ReplyToTopicId).HasColumnName("ReplyToTopicID");

                entity.Property(e => e.RootTopicId).HasColumnName("RootTopicID");

                entity.Property(e => e.Title)
                    .IsRequired()
                    .HasMaxLength(200);

                entity.HasOne(d => d.Forum)
                    .WithMany(p => p.Topic)
                    .HasForeignKey(d => d.ForumId)
                    .HasConstraintName("FK_Topic_Forum");

                entity.HasOne(d => d.ModifiedByUser)
                    .WithMany(p => p.TopicModifiedByUser)
                    .HasForeignKey(d => d.ModifiedByUserId)
                    .HasConstraintName("FK_Topic_ModifiedByUser");

                entity.HasOne(d => d.Owner)
                    .WithMany(p => p.TopicOwner)
                    .HasForeignKey(d => d.OwnerId)
                    .OnDelete(DeleteBehavior.ClientSetNull)
                    .HasConstraintName("FK_Topic_Owner");

                entity.HasOne(d => d.ReplyToTopic)
                    .WithMany(p => p.InverseReplyToTopic)
                    .HasForeignKey(d => d.ReplyToTopicId)
                    .HasConstraintName("FK_Topic_ReplyToTopic");

                entity.HasOne(d => d.RootTopic)
                    .WithMany(p => p.InverseRootTopic)
                    .HasForeignKey(d => d.RootTopicId)
                    .HasConstraintName("FK_Topic_RootTopic");
            });

            modelBuilder.Entity<User>(entity =>
            {
                entity.Property(e => e.Id).HasColumnName("ID");

                entity.Property(e => e.Description).HasMaxLength(1000);

                entity.Property(e => e.Name)
                    .IsRequired()
                    .HasMaxLength(50);

                entity.Property(e => e.PasswordHash)
                    .IsRequired()
                    .HasMaxLength(200);
            });
        }
    }
}
