#ifndef _LINUX_SUS_SLIVA
#include <linux/string.h>
#include <linux/types.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/printk.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/suspicious.h>
#define getname_safe(name) (name == NULL ? ERR_PTR(-EINVAL) : getname(name))
#define putname_safe(name) (IS_ERR(name) ? NULL : putname(name))
#define uid_matches() (getuid() >= 2000)
#define SUS_VERSION 5000
static char sus_words[99][99] = {
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s",
"my/big/ball/s"
};
static int sus_paths_count = 0;
static uid_t getuid(void) {

	const struct cred* const credentials = current_cred();

	if (credentials == NULL) {
		return 0;
	}

	return credentials->uid.val;

}
int is_suspicious_path(const struct path* const file)
{
	size_t index = 0;
	size_t size = 4096;
	int res = -1;
	int status = 0;
	char* path = NULL;
	char* ptr = NULL;
	char* end = NULL;

	if (!uid_matches() || file == NULL) {
		status = 0;
		goto out;
	}

	path = kmalloc(size, GFP_KERNEL);

	if (path == NULL) {
		status = -1;
		goto out;
	}

	ptr = d_path(file, path, size);

	if (IS_ERR(ptr)) {
		status = -1;
		goto out;
	}

	end = mangle_path(path, ptr, " \t\n\\");

	if (!end) {
		status = -1;
		goto out;
	}

	res = end - path;
	path[(size_t) res] = '\0';
	
    for (index = 0; index < ARRAY_SIZE(sus_words); index++) {
		const char* const name = sus_words[index];

		if (memcmp(name, path, strlen(name)) == 0) {
			printk(KERN_INFO "suspicious-fs: file or directory access to suspicious path '%s' won't be allowed to process with UID %i\n", name, getuid());
            sus_paths_count++;
			status = 1;
			goto out;
		}
	}

	out:
		kfree(path);

	return status;
}

int suspicious_path(const struct filename* const name)
{
	int status = 0;
	int ret = 0;
	struct path path;

	if (IS_ERR(name)) {
		return -1;
	}

	if (!uid_matches() || name == NULL) {
		return 0;
	}

	ret = kern_path(name->name, LOOKUP_FOLLOW, &path);

	if (!ret) {
		status = is_suspicious_path(&path);
		path_put(&path);
	}

	return status;

}

int get_sus_multi(int arg) {
    if (arg==0) return sus_paths_count;
	if (arg==1) return 100;
  if (arg==2) return SUS_VERSION;
	return 10;
}
int set_suspicious_path(char * sus_path,int index) {
	strcpy(sus_words[index],sus_path);
	return 10;
}
#define _LINUX_SUS_SLIVA
#endif
