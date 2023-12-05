# Filesystem 

### /proc filesystem ###

- It's representing some parts of kernel 
- Also, it provides a way to interact with kernel if the feature is allowed
-  The /proc/ directory — also called the proc file system — contains a hierarchy of special files which represent the current state of the kernel — allowing applications and users to peer into the kernel's view of the system.
- Usually keeps small amount of very specific data in each files, but sometimes it contains complex data as well
- proc file can be created with the below functions

```
#include <linux/proc_fs.h>

/* Not available in RHEL7 or later */
struct proc_dir_entry *create_proc_entry(const char *name, mode_t mode,
           struct proc_dir_entry *parent);
        
/* Avaialble in all versions *      
struct proc_dir_entry *proc_create(
  const char *name, umode_t mode, struct proc_dir_entry *parent,
  const struct file_operations *proc_fops);
  
struct proc_dir_entry *proc_create_data(const char *name, umode_t mode,
          struct proc_dir_entry *parent,
          const struct file_operations *proc_fops,
          void *data);
  
/*
 * Remove a /proc entry and free it if it's not currently in use.
 */
void remove_proc_entry(const char *name, struct proc_dir_entry *parent);

struct proc_dir_entry *proc_symlink(const char *name,
    struct proc_dir_entry *parent, const char *dest);
    
struct proc_dir_entry *proc_mkdir(const char *name,
    struct proc_dir_entry *parent);   
```

- Example

```
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>

#define NODE  "myproc"

int param = 100;
struct proc_dir_entry *my_proc;

ssize_t my_proc_read(struct file *file, char __user * buf,
         size_t len, loff_t * offset)
{
  char mydata[20];

  sprintf(mydata, "%d\n", param);
  if (*offset > strlen(mydata))
    return 0;
  *offset = strlen(mydata) + 1;
  return strlen(mydata) - copy_to_user(buf, mydata, strlen(mydata));
}

ssize_t my_proc_write(struct file * file, const char __user * buffer,
          size_t count, loff_t * pos)
{
  char *str;
  str = kmalloc(count, GFP_KERNEL);
  if (copy_from_user(str, buffer, count)) {
    kfree(str);
    return -EFAULT;
  }
  sscanf(str, "%d", &param);
  printk("param has been set to %d\n", param);
  kfree(str);
  return count;
}

struct file_operations myfops = {
  .read = my_proc_read,
  .write = my_proc_write,
};

int __init my_init(void)
{
  my_proc = proc_create(NODE, 0666, NULL, &myfops);
  if (!my_proc) {
    printk("I failed to make %s\n", NODE);
    return -1;
  }
  printk("I created %s\n", NODE);
  return 0;
}

void __exit my_exit(void)
{
  if (my_proc) {
    remove_proc_entry(NODE, NULL);
    printk("Removed %s\n", NODE);
  }
}

module_init(my_init);
module_exit(my_exit);
```

- Example : passing data

```
/* my_new_proc.c */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/init.h>

#define NODE_DIR  "my_proc_dir"
#define NODE_1    "param1"
#define NODE_2    "param2"

int param_1 = 100, param_2 = 200;
struct proc_dir_entry *my_proc_dir, *my_proc_1, *my_proc_2;

ssize_t my_proc_read(struct file *file, char __user * buf,
         size_t len, loff_t * offset)
{
  char mydata[20];

  if (PDE_DATA(file_inode(file)) == (void *)1)
    sprintf(mydata, "%d\n", param_1);
  if (PDE_DATA(file_inode(file)) == (void *)2)
    sprintf(mydata, "%d\n", param_2);

  if (*offset > strlen(mydata))
    return 0;
  *offset = strlen(mydata) + 1;
  return strlen(mydata) - copy_to_user(buf, mydata, strlen(mydata));
}

ssize_t my_proc_write(struct file * file, const char __user * buffer,
          size_t count, loff_t * pos)
{
  char *str = kmalloc(count, GFP_KERNEL);
  if (copy_from_user(str, buffer, count)) {
    kfree(str);
    return -EFAULT;
  }
  if (PDE_DATA(file_inode(file)) == (void *)1) {
    sscanf(str, "%d", &param_1);
    printk("param_1 has been set to %d\n", param_1);
    kfree(str);
    return count;
  }
  if (PDE_DATA(file_inode(file)) == (void *)2) {
    sscanf(str, "%d", &param_2);
    printk("PARAM2 is set to %d\n", param_2);
    kfree(str);
    return count;
  }
  kfree(str);
  return -EINVAL;
}

struct file_operations myfops = {
  .read = my_proc_read,
  .write = my_proc_write,
};

int __init my_init(void)
{
  my_proc_dir = proc_mkdir(NODE_DIR, NULL);

  my_proc_1 =
      proc_create_data(NODE_1, 0666, my_proc_dir, &myfops, (void *)1);

  my_proc_2 =
      proc_create_data(NODE_2, 0666, my_proc_dir, &myfops, (void *)2);

  return 0;
}

void __exit my_exit(void)
{
  remove_proc_entry(NODE_1, my_proc_dir);
  remove_proc_entry(NODE_2, my_proc_dir);
  remove_proc_entry(NODE_DIR, NULL);
}

module_init(my_init);
module_exit(my_exit);
```

- Example: Sending signal

```
/* sig_proc.c */
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/init.h>
#include <asm/switch_to.h>

#define NODE_DIR  "my_sig_dir"
#define NODE_1    "pid"
#define NODE_2    "signal"

struct proc_dir_entry *proc_sigdir, *proc_pid, *proc_signal;
int sig_pid = -1, sig_tosend = SIGUSR1;
struct task_struct *sig_tsk = NULL;

ssize_t my_proc_read(struct file *file, char __user * buf,
             size_t len, loff_t * offset)
{
  char data[1024];

  if (PDE_DATA(file_inode(file)) == &proc_pid)
    sprintf(data, "%d\n", sig_pid);
  if (PDE_DATA(file_inode(file)) == &proc_signal)
    sprintf(data, "%d\n", sig_tosend);


    if (*offset > strlen(data))
          return 0;
      *offset = strlen(data) + 1;
        return strlen(data) - copy_to_user(buf, data, strlen(data));

}

ssize_t my_proc_write(struct file * file, const char __user * buffer,
              size_t count, loff_t * pos)
{
  char *str = kmalloc(count, GFP_KERNEL);
  if (copy_from_user(str, buffer, count)) {
    kfree(str);
    return -EFAULT;
  }
  if (PDE_DATA(file_inode(file)) == &proc_pid) {
    sscanf(str, "%d", &sig_pid);
    printk("sig_pid has been set to %d\n", sig_pid);
//    sig_tsk = find_task_by_pid_ns(sig_pid, &init_pid_ns);
    sig_tsk = pid_task(find_pid_ns(sig_pid, &init_pid_ns), PIDTYPE_PID);
    kfree(str);
    return count;
  }
  if (PDE_DATA(file_inode(file)) == &proc_signal) {
    sscanf(str, "%d", &sig_tosend);
    printk("sig_tosend has been set to %d\n", sig_tosend);
    if (!sig_tsk) {
      sig_tsk = current;
      sig_pid = (int)current->pid;
    }
    printk("Send signal %d to process %d\n", sig_tosend, sig_pid);
    send_sig(sig_tosend, sig_tsk, 0);
    kfree(str);
    return count;
  }
  kfree(str);
  return -EINVAL;
}

struct file_operations myfops = {
    .read = my_proc_read,
      .write = my_proc_write,
};

int __init my_init(void)
{
  proc_sigdir = proc_mkdir(NODE_DIR, NULL);

  proc_pid = proc_create_data(NODE_1, 0666, proc_sigdir, &myfops, &proc_pid);

  proc_signal = proc_create_data(NODE_2, 0666, proc_sigdir, &myfops, &proc_signal);

  return 0;
}

void __exit my_exit(void)
{
  remove_proc_entry(NODE_1, proc_sigdir);
  remove_proc_entry(NODE_2, proc_sigdir);
  remove_proc_entry(NODE_DIR, NULL);
}

module_init(my_init);
module_exit(my_exit);

MODULE_LICENSE("GPL");
```

### Filesystem related functions ###

- Registering/Unregistering filesystem

```
/**
 *  register_filesystem - register a new filesystem
 *  @fs: the file system structure
 *
 *  Adds the file system passed to the list of file systems the kernel
 *  is aware of for mount and other syscalls. Returns 0 on success,
 *  or a negative errno code on an error.
 *
 *  The &struct file_system_type that is passed is linked into the kernel 
 *  structures and must not be freed until the file system has been
 *  unregistered.
 */

int register_filesystem(struct file_system_type * fs)
{
  int res = 0;
  struct file_system_type ** p;

  BUG_ON(strchr(fs->name, '.'));
  if (fs->next)
    return -EBUSY;
  write_lock(&file_systems_lock);
  p = find_filesystem(fs->name, strlen(fs->name));
  if (*p)
    res = -EBUSY;
  else
    *p = fs;
  write_unlock(&file_systems_lock);
  return res;
}


/**
 *  unregister_filesystem - unregister a file system
 *  @fs: filesystem to unregister
 *
 *  Remove a file system that was previously successfully registered
 *  with the kernel. An error is returned if the file system is not found.
 *  Zero is returned on a success.
 *  
 *  Once this function has returned the &struct file_system_type structure
 *  may be freed or reused.
 */
 
int unregister_filesystem(struct file_system_type * fs)
{ 
  struct file_system_type ** tmp;
  
  write_lock(&file_systems_lock);
  tmp = &file_systems;
  while (*tmp) {
    if (fs == *tmp) {
      *tmp = fs->next;
      fs->next = NULL;
      write_unlock(&file_systems_lock);
      synchronize_rcu();
      return 0;
    }
    tmp = &(*tmp)->next;
  }
  write_unlock(&file_systems_lock);

  return -EINVAL;
}
```

- Example : Ceph

```
 952 static struct file_system_type ceph_fs_type = {
 953   .owner    = THIS_MODULE,
 954   .name   = "ceph",
 955   .mount    = ceph_mount,
 956   .kill_sb  = ceph_kill_sb,
 957   .fs_flags = FS_RENAME_DOES_D_MOVE,
 958 };
 
 
 964 static int __init init_ceph(void)
 965 {
 966   int ret = init_caches();
 967   if (ret)
 968     goto out;
 969 
 970   ceph_flock_init();
 971   ceph_xattr_init();
 972   ret = register_filesystem(&ceph_fs_type);
 973   if (ret)
 974     goto out_icache;
..
}

 987 static void __exit exit_ceph(void)
 988 {
 989   dout("exit_ceph\n");
 990   unregister_filesystem(&ceph_fs_type);
 991   ceph_xattr_exit();
 992   destroy_caches();
 993 }
```

- How to find filesystems registered in a vmcore file

```
crash> file_systems
file_systems = $1 = (struct file_system_type *) 0xffffffff81997260 <sysfs_fs_type>
crash> list -o file_system_type.next -s file_system_type.name 0xffffffff81997260
ffffffff81997260
  name = 0xffffffff8185d5e7 "sysfs"
ffffffff81997ca0
  name = 0xffffffff8184209e "rootfs"
ffffffff819924e0
  name = 0xffffffff8184250a "bdev"
ffffffff81996d00
  name = 0xffffffff818364e6 "proc"
ffffffff8194b9c0
  name = 0xffffffff8185780e "cgroup"
ffffffff8194cca0
  name = 0xffffffff8183d71c "cpuset"
ffffffff8197d040
  name = 0xffffffff81869566 "tmpfs"
ffffffff819ccfa0
  name = 0xffffffff81869563 "devtmpfs"
ffffffff81998520
  name = 0xffffffff81844e76 "debugfs"
ffffffff8199c3a0
  name = 0xffffffff81845c90 "securityfs"
ffffffff819e05e0
  name = 0xffffffff818a047b "sockfs"
ffffffff81989e60
  name = 0xffffffff818418de "pipefs"
ffffffff81993e20
  name = 0xffffffff818437c2 "anon_inodefs"
ffffffff819976e0
  name = 0xffffffff818449f4 "configfs"
ffffffff81997800
  name = 0xffffffff81844b0f "devpts"
ffffffff81997ce0
  name = 0xffffffff81844b91 "ramfs"
ffffffff81998080
  name = 0xffffffff81844bcf "hugetlbfs"
ffffffff81998460
  name = 0xffffffff81844c19 "autofs"
ffffffff81998560
  name = 0xffffffff81844ec1 "pstore"
ffffffff8199a1e0
  name = 0xffffffff81845339 "mqueue"
ffffffff819a02e0
  name = 0xffffffff8184660a "selinuxfs"
ffffffffa022c900
  name = 0xffffffffa0221dc9 "ext3"
ffffffffa022c940
  name = 0xffffffffa0221dce "ext2"
ffffffffa022c000
  name = 0xffffffffa0221680 "ext4"
ffffffffa027fb80
  name = 0xffffffffa02769d0 "rpc_pipefs"
ffffffffa0304340
  name = 0xffffffffa02fe98a "nfsd"
ffffffffa04871e0
  name = 0xffffffffa0481d16 "nfs"
ffffffffa0487160
  name = 0xffffffffa0481d11 "nfs4"
ffffffffa04390c0
  name = 0xffffffffa04380b2 "binfmt_misc"
ffffffffa0542e80
  name = 0xffffffffa05294bc "xfs"
ffffffffa0452000
  name = 0xffffffffa04511e6 "msdos"
ffffffffa044c000
  name = 0xffffffffa044b259 "vfat"
ffffffffa0666380
  name = 0xffffffffa065a116 "btrfs"
ffffffffa06bd060
  name = 0xffffffffa06bc135 "fuseblk"
ffffffffa06bd0a0
  name = 0xffffffffa06bc0fe "fuse"
ffffffffa06bd160
  name = 0xffffffffa06bc1ee "fusectl"
crash>
```

- mount filesystem
  - do_mount() will call 

```
 56 struct vfsmount {
 57   struct dentry *mnt_root;  /* root of the mounted tree */
 58   struct super_block *mnt_sb; /* pointer to superblock */
 59   int mnt_flags;
 60 };
 
1273 struct super_block {
1274   struct list_head  s_list;   /* Keep this first */
1275   dev_t     s_dev;    /* search kernel/internals/index; _not_ kdev_t */
1276   unsigned char   s_blocksize_bits;
1277   unsigned long   s_blocksize;
1278   loff_t      s_maxbytes; /* Max file size */
1279   struct file_system_type *s_type;
1280   const struct super_operations *s_op;
1281   const struct dquot_operations *dq_op;
1282   const struct quotactl_ops *s_qcop;
1283   const struct export_operations *s_export_op;
1284   unsigned long   s_flags;
1285   unsigned long   s_magic;
1286   struct dentry   *s_root;
1287   struct rw_semaphore s_umount;
1288   int     s_count;
1289   atomic_t    s_active;
1290 #ifdef CONFIG_SECURITY
1291   void                    *s_security;
1292 #endif
1293   const struct xattr_handler **s_xattr;
1294 
1295   struct list_head  s_inodes; /* all inodes */
```

- Example: Ceph

```
 866 static struct dentry *ceph_mount(struct file_system_type *fs_type,
 867            int flags, const char *dev_name, void *data)
 868 {
 869   struct super_block *sb;
  ...
 902   sb = sget(fs_type, compare_super, ceph_set_super, flags, fsc);
 903   if (IS_ERR(sb)) {
 904     res = ERR_CAST(sb);
 905     goto out;
 906   }  
 ...
 922   res = ceph_real_mount(fsc, path);
 923   if (IS_ERR(res))
 924     goto out_splat;
 925   dout("root %p inode %p ino %llx.%llx\n", res,
 926        res->d_inode, ceph_vinop(res->d_inode));
 927   return res;
  ...
}
```

- Superblock metadata operations : super_operations

```
struct super_operations {
    struct inode *(*alloc_inode)(struct super_block *sb);
  void (*destroy_inode)(struct inode *);

    void (*dirty_inode) (struct inode *, int flags);
  int (*write_inode) (struct inode *, struct writeback_control *wbc);
  int (*drop_inode) (struct inode *);
  void (*evict_inode) (struct inode *);
  void (*put_super) (struct super_block *);
  int (*sync_fs)(struct super_block *sb, int wait);
  int (*freeze_fs) (struct super_block *);
  int (*unfreeze_fs) (struct super_block *);
  int (*statfs) (struct dentry *, struct kstatfs *);
  int (*remount_fs) (struct super_block *, int *, char *);
  void (*umount_begin) (struct super_block *);

  int (*show_options)(struct seq_file *, struct dentry *);
  int (*show_devname)(struct seq_file *, struct dentry *);
  int (*show_path)(struct seq_file *, struct dentry *);
  int (*show_stats)(struct seq_file *, struct dentry *);
#ifdef CONFIG_QUOTA
  ssize_t (*quota_read)(struct super_block *, int, char *, size_t, loff_t);
  ssize_t (*quota_write)(struct super_block *, int, const char *, size_t, loff_t);
#endif
  int (*bdev_try_to_free_page)(struct super_block*, struct page*, gfp_t);
  int (*nr_cached_objects)(struct super_block *);
  void (*free_cached_objects)(struct super_block *, int);
};
```

- Example: Ceph

```
static const struct super_operations ceph_super_ops = {
  .alloc_inode  = ceph_alloc_inode,
  .destroy_inode  = ceph_destroy_inode,
  .write_inode    = ceph_write_inode,
  .drop_inode = ceph_drop_inode,
  .sync_fs        = ceph_sync_fs,
  .put_super  = ceph_put_super,
  .show_options   = ceph_show_options,
  .statfs   = ceph_statfs,
  .umount_begin   = ceph_umount_begin,
};
```

- inode operations from inode

```
struct inode {
  umode_t     i_mode;
  unsigned short    i_opflags;
  kuid_t      i_uid;
  kgid_t      i_gid;
  unsigned int    i_flags;

#ifdef CONFIG_FS_POSIX_ACL
  struct posix_acl  *i_acl;
  struct posix_acl  *i_default_acl;
#endif

  const struct inode_operations *i_op;
  struct super_block  *i_sb;
  struct address_space  *i_mapping;

#ifdef CONFIG_SECURITY
  void      *i_security;
#endif

  /* Stat data, not accessed from path walking */
  unsigned long   i_ino;
  /*
   * Filesystems may only read i_nlink directly.  They shall use the
   * following functions for modification:
   *
   *    (set|clear|inc|drop)_nlink
   *    inode_(inc|dec)_link_count
   */
  union {
    const unsigned int i_nlink;
    unsigned int __i_nlink;
  };
  dev_t     i_rdev;
  loff_t      i_size;
  struct timespec   i_atime;
  struct timespec   i_mtime;
  struct timespec   i_ctime;
  spinlock_t    i_lock; /* i_blocks, i_bytes, maybe i_size */
  unsigned short          i_bytes;
  unsigned int    i_blkbits;
  blkcnt_t    i_blocks;

#ifdef __NEED_I_SIZE_ORDERED
  seqcount_t    i_size_seqcount;
#endif

  /* Misc */
  unsigned long   i_state;
  struct mutex    i_mutex;

  unsigned long   dirtied_when; /* jiffies of first dirtying */

  struct hlist_node i_hash;
  struct list_head  i_wb_list;  /* backing dev IO list */
  struct list_head  i_lru;    /* inode LRU list */
  struct list_head  i_sb_list;
  union {
    struct hlist_head i_dentry;
    struct rcu_head   i_rcu;
  };
  u64     i_version;
  atomic_t    i_count;
  atomic_t    i_dio_count;
  atomic_t    i_writecount;
  const struct file_operations  *i_fop; /* former ->i_op->default_file_ops */
  struct file_lock  *i_flock;
  struct address_space  i_data;
#ifdef CONFIG_QUOTA
  struct dquot    *i_dquot[MAXQUOTAS];
#endif
  struct list_head  i_devices;
  union {
    struct pipe_inode_info  *i_pipe;
    struct block_device *i_bdev;
    struct cdev   *i_cdev;
  };
  
  __u32     i_generation;
    
#ifdef CONFIG_FSNOTIFY
  __u32     i_fsnotify_mask; /* all events this inode cares about */
  struct hlist_head i_fsnotify_marks;
#endif

#ifdef CONFIG_IMA
  atomic_t    i_readcount; /* struct files open RO */
#endif
  void      *i_private; /* fs or device private pointer */
};

struct inode_operations {
  struct dentry * (*lookup) (struct inode *,struct dentry *, unsigned int);
  void * (*follow_link) (struct dentry *, struct nameidata *);
  int (*permission) (struct inode *, int);
  struct posix_acl * (*get_acl)(struct inode *, int);

  int (*readlink) (struct dentry *, char __user *,int);
  void (*put_link) (struct dentry *, struct nameidata *, void *);

  int (*create) (struct inode *,struct dentry *, umode_t, bool);
  int (*link) (struct dentry *,struct inode *,struct dentry *);
  int (*unlink) (struct inode *,struct dentry *);
  int (*symlink) (struct inode *,struct dentry *,const char *);
  int (*mkdir) (struct inode *,struct dentry *,umode_t);
  int (*rmdir) (struct inode *,struct dentry *);
  int (*mknod) (struct inode *,struct dentry *,umode_t,dev_t);
  int (*rename) (struct inode *, struct dentry *,
      struct inode *, struct dentry *);
  int (*setattr) (struct dentry *, struct iattr *);
  int (*getattr) (struct vfsmount *mnt, struct dentry *, struct kstat *);
  int (*setxattr) (struct dentry *, const char *,const void *,size_t,int);
  ssize_t (*getxattr) (struct dentry *, const char *, void *, size_t);
  ssize_t (*listxattr) (struct dentry *, char *, size_t);
  int (*removexattr) (struct dentry *, const char *);
  int (*fiemap)(struct inode *, struct fiemap_extent_info *, u64 start,
          u64 len);
  int (*update_time)(struct inode *, struct timespec *, int);
  int (*atomic_open)(struct inode *, struct dentry *,
         struct file *, unsigned open_flag,
         umode_t create_mode, int *opened);
} ____cacheline_aligned;
```

- Example: Ceph

```
static int fill_inode(struct inode *inode,
          struct ceph_mds_reply_info_in *iinfo,
          struct ceph_mds_reply_dirfrag *dirinfo,
          struct ceph_mds_session *session, 
          unsigned long ttl_from, int cap_fmode,
          struct ceph_cap_reservation *caps_reservation)
{ 
...
  switch (inode->i_mode & S_IFMT) {
  case S_IFIFO:
  case S_IFBLK:
  case S_IFCHR:
  case S_IFSOCK:
    init_special_inode(inode, inode->i_mode, inode->i_rdev);
    inode->i_op = &ceph_file_iops;
    break;
  case S_IFREG:
    inode->i_op = &ceph_file_iops;
    inode->i_fop = &ceph_file_fops;
    break;
  case S_IFLNK:
    inode->i_op = &ceph_symlink_iops;
    if (!ci->i_symlink) {
      u32 symlen = iinfo->symlink_len;
      char *sym;
...
}


const struct inode_operations ceph_file_iops = {
  .permission = ceph_permission,
  .setattr = ceph_setattr,
  .getattr = ceph_getattr,
  .setxattr = ceph_setxattr,
  .getxattr = ceph_getxattr,
  .listxattr = ceph_listxattr,
  .removexattr = ceph_removexattr,
};

const struct file_operations ceph_file_fops = {
  .open = ceph_open,
  .release = ceph_release,
  .llseek = ceph_llseek,
  .read = do_sync_read,
  .write = do_sync_write,
  .aio_read = ceph_aio_read,
  .aio_write = ceph_aio_write,
  .mmap = ceph_mmap,
  .fsync = ceph_fsync,
  .lock = ceph_lock,
  .flock = ceph_flock,
  .splice_read = generic_file_splice_read,
  .splice_write = generic_file_splice_write,
  .unlocked_ioctl = ceph_ioctl,
  .compat_ioctl = ceph_ioctl,
  .fallocate  = ceph_fallocate,
};
```



---
[Back to topic list](https://sungju.github.io/kernel/internals/index)
