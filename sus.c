#ifdef CONFIG_SLIVA_PATCH
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
#define SUS_VERSION 6000
#define SUS_DELETED 100
#define SUS_OK 10
#define SUS_FAIL 9
#define SUS_PATHS_SIZE 10
static char sus_paths[SUS_PATHS_SIZE][50] = {
"ex/am/pl/e",
"ex/am/pl/e",
"ex/am/pl/e",
"ex/am/pl/e",
"ex/am/pl/e",
"ex/am/pl/e",
"ex/am/pl/e",
"ex/am/pl/e",
"ex/am/pl/e",
"ex/am/pl/e"
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
	
    for (index = 0; index < ARRAY_SIZE(sus_paths); index++) {
		const char* const name = sus_paths[index];

		if (memcmp(name, path, strlen(name)) == 0) {
			printk(KERN_INFO "suspicious-fs: file or directory access to suspicious path '%s' won't be allowed to process with UID %i\n", name, getuid());
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
int sus_try_add(char * sus_path) {
	int sus_i = 0;
	bool sus_writed = false;
	for (sus_i = 0;sus_i<SUS_PATHS_SIZE;sus_i++) {
		if (sus_paths[sus_i]=="ex/am/pl/e") {
			strcpy(sus_paths[sus_i],sus_path);
			sus_writed = true;
			sus_paths_count++;
			printk(KERN_INFO "suspicious-fs: writed %s to sus_paths[%d]", sus_path, sus_i);
			break;
		}
	}
	if (sus_writed==true) return SUS_OK;
	return SUS_FAIL;
}
int sus_clean_all() {
	int sus_i = 0;
	for (sus_i = 0;sus_i<SUS_PATHS_SIZE;sus_i++) {
		strcpy(sus_paths[sus_i],"ex/am/pl/e");
		printk(KERN_INFO "suspicious-fs: clean sus_paths[%d]", sus_i);
	}
	sus_paths_count = 0;
	return SUS_OK;
}
int sus_auto_add() {
	sus_try_add("/stoarge/emulated/0/TWRP");
	sus_try_add("/system/addon.d");
	return SUS_OK;
}
int get_sus_multi(int arg) {
    if (arg==0) return sus_paths_count;
	if (arg==1) return SUS_DELETED;
    if (arg==2) return SUS_VERSION;
	if (arg==3) return sus_auto_add();
	if (arg==4) return sus_clean_all();
	if (arg==5) return SUS_PATHS_SIZE;
	return SUS_FAIL;
}
int set_suspicious_path(char * sus_path,int index) {
	if (index==SUS_PATHS_SIZE) {
		return sus_try_add(sus_path);
	} else {
	strcpy(sus_paths[index],sus_path);
	}
	return SUS_OK;
}
#endif
