#ifndef _LINUX_SUSPICIOUS_H_
#define _LINUX_SUSPICIOUS_H_

#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/cred.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/printk.h>
#include <linux/mount.h>
#include <linux/namei.h>


int is_suspicious_path(const struct path* const file);
int is_suspicious_mount(struct vfsmount* const mnt, const struct path* const root);
int suspicious_path(const struct filename* const name);
int get_sus_multi(int);
int set_suspicious_path(char *, int);
int set_suspicious_mount(char *, int);
#endif
