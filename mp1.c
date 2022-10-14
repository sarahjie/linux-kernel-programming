#define LINUX

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include "mp1_given.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("xjie3");
MODULE_DESCRIPTION("CS-423 MP1");

#define DIRECTORY "mp1"
#define FILENAME "status"
#define MAX_STR_LEN 32
#define DEBUG 1

#define SZ 1024
//static char kernel_buf[SZ];

static struct proc_dir_entry *dir_mp1;
static struct proc_dir_entry *status_file;
LIST_HEAD(list_head_mp1);
static struct timer_list my_timer;
static struct workqueue_struct *wq = NULL;
static DEFINE_SPINLOCK(lock_sp);

struct pid_time_struct {
	pid_t pid;
	unsigned long time_use;
	struct list_head list_head_struct;
};


static void update_cpu_time(struct work_struct *work) {
	struct pid_time_struct *proc, *tmp;
	unsigned long cpu_time, flags;
	spin_lock_irqsave(&lock_sp, flags);
	list_for_each_entry_safe(proc, tmp, &list_head_mp1, list_head_struct) {
		if (get_cpu_use(proc->pid, &cpu_time) == 0) {
			//update cpu time
			proc->time_use = cpu_time;
		}
		else {
			list_del(&proc->list_head_struct);
			kfree(proc);
		}
	}
	spin_unlock_irqrestore(&lock_sp, flags);
}

DECLARE_WORK(mp1_proc, update_cpu_time);

static void enq_work(struct timer_list *timer) {
	queue_work(wq, &mp1_proc);
	if(mod_timer(&my_timer, jiffies + msecs_to_jiffies(5000)) != 0){
		printk("mod timer failed at enqueue \n");
	}
}

static ssize_t mp1_read(struct file *filp, char __user *user_buf, size_t size, loff_t *off)
{
	
        
	loff_t offset = *off;
	#ifdef DEBUG
		printk("offset : %lld\n", offset);
	#endif
	size_t remaining;
	unsigned long flags;
	struct pid_time_struct *proc;
	
	if (!access_ok(user_buf, size)) {
		#ifdef DEBUG
		printk("access not ok\n");
		#endif
		return -EINVAL;
	}

	//pr_info("proc file read\n");
    
	if (offset < 0)
		return -EINVAL;
	
	if (offset > 0){
		return 0;
	}
	
	if (offset >= SZ || size == 0)
		return 0;

	if (size > SZ - offset)
		size = SZ - offset;

	
	
	ssize_t list_size=0;
	spin_lock_irqsave(&lock_sp, flags);
	list_for_each_entry(proc, &list_head_mp1, list_head_struct)
		list_size++;
	spin_unlock_irqrestore(&lock_sp, flags);

	#ifdef DEBUG
		printk("list_size: %d\n", list_size);
	#endif
	
	char* kbuf = kmalloc(size, GFP_KERNEL);
	if (kbuf == NULL) {
		#ifdef DEBUG
		printk("read buffer error\n");
		#endif
		return -ENOMEM;
		
	}

	ssize_t bytes_read=0;
	
	spin_lock_irqsave(&lock_sp, flags);
	list_for_each_entry(proc, &list_head_mp1, list_head_struct) {
		bytes_read += sprintf(kbuf + bytes_read, "%d: %lu\n", proc->pid, proc->time_use);
		//
		#ifdef DEBUG
		printk("read %d: %lu\n", proc->pid, proc->time_use);
		#endif
		//
		if (bytes_read >= list_size * MAX_STR_LEN){
			#ifdef DEBUG
			printk("too many processes\n");
			#endif
			break;
		}
		
	}
	/*if(strlen(kernel_buf) + strlen(kbuf) + 1 > SZ){
			printk(KERN_ALERT "proccess too much\n");
	}else{
			strcat(kernel_buf, kbuf);
	}*/
	spin_unlock_irqrestore(&lock_sp, flags);
	
	//return bytes that could not be copied
	if (bytes_read >= size){
		bytes_read=size;
		
	}
			
	remaining = copy_to_user(user_buf, kbuf, bytes_read);
	
	if (remaining == size) {
		pr_err("copy_to_user failed\n");
		
		return -EFAULT;
    }
	kfree(kbuf);
	bytes_read -= remaining;
	//size -= remaining;
	*off = offset + bytes_read;
	return bytes_read;
}

static ssize_t mp1_write(struct file *filp, const char __user *user_buf, size_t size, loff_t *off)
{
       
        size_t remaining;
	loff_t offset = *off;
	pr_info("proc file write\n");
    
	if (offset < 0)
		return -EINVAL;

	if (offset >= SZ || size == 0)
		return 0;

	if (size > SZ - offset)
		size = SZ - offset;
	
	
	
	
	pid_t pid;
	int error;
	struct pid_time_struct *proc;
	unsigned long flags;
	char *kbuf;

	// buffer accessiblity sanity check
	if (!access_ok(user_buf, size)) {
		return -EINVAL;
	}

	kbuf = kmalloc(size + 1, GFP_KERNEL);
	if (kbuf == NULL) {
		return -ENOMEM;
	}

	//return bytes that could not be copied
	remaining = copy_from_user(kbuf, user_buf, size);
	//strcat(kernel_buf,kbuf);
	if (remaining == size) {
		pr_err("copy_from_user failed\n");
		kfree(kbuf);
		return -EFAULT;

	}
	
	// end kubf array
	kbuf[size] = '\0';
	if ((error = kstrtoint(kbuf, 10, &pid))) {
		
		kfree(kbuf);
		return error;
	}

	proc = kmalloc(sizeof(struct pid_time_struct), GFP_KERNEL);

	proc->pid = pid;
	//proc->time_use = 0;
	//sscanf(kbuf, "%u", &proc->pid);

	//proc->pid = (pid_t)simple_strtol(kbuf, NULL, 10);
	if(get_cpu_use((int)(proc->pid), &(proc->time_use)) != 0){
		printk(KERN_ALERT "get_cpu_use error\n");
		kfree(proc);
		return 0;
	}
	
	spin_lock_irqsave(&lock_sp, flags);
	list_add_tail(&proc->list_head_struct, &list_head_mp1);
	spin_unlock_irqrestore(&lock_sp, flags);
	

	size -= remaining;
	
	
	kfree(kbuf);
	return size;
}


static const struct proc_ops mp1_file = {
	.proc_read = mp1_read,
	.proc_write = mp1_write,

};

// mp1_init - Called when module is loaded
int __init mp1_init(void)
{
	#ifdef DEBUG
   	printk(KERN_ALERT "MP1 MODULE LOADING for debuging\n");
   	#endif
	int error = 0;

	// Create /proc/mp1 directory
	dir_mp1 = proc_mkdir(DIRECTORY, NULL);
	if (dir_mp1 == NULL) {
		
		printk(KERN_ALERT "/proc/" DIRECTORY " creation failed\n");
		return -ENOMEM;
	}

	// Create /proc/mp1/status entry
	status_file = proc_create(FILENAME, 0666, dir_mp1, &mp1_file);
	if (status_file == NULL) {
		
		printk(KERN_ALERT "/proc/" DIRECTORY "/" FILENAME " entry failed\n");
		return -ENOMEM;
	}

	//setup timer
	timer_setup(&my_timer, enq_work, 0);
	
	if(mod_timer(&my_timer, jiffies + msecs_to_jiffies(5000)) != 0){
		printk("mod_timer error at mp1_init");
	}

	wq = create_singlethread_workqueue("mp1");

	return error;
}

// mp1_exit - Called when module is unloaded
void __exit mp1_exit(void)
{
	struct pid_time_struct *proc, *tmp;

	remove_proc_entry(FILENAME, dir_mp1);
	remove_proc_entry(DIRECTORY, NULL);

	del_timer(&my_timer);

	flush_workqueue(wq);
	destroy_workqueue(wq);

	// Clear list and free up memory
	list_for_each_entry_safe(proc, tmp, &list_head_mp1, list_head_struct) {
		list_del(&proc->list_head_struct);
		kfree(proc);
	}
}

// Register init and exit funtions
module_init(mp1_init);
module_exit(mp1_exit);
