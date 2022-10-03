# mp1-sarahjie
mp1-sarahjie created by GitHub Classroom <br />
**Brief Implementation Explanation**<br />
proc_read: copy the information to the user buffer, update the offset, return bytes read. Return negative if failed
proc_write: take information from user buffer, update the offset, return bytes written. Return negative if failed
linux kernel linked list: for each process add the node to the tail of the linked list. Each node contains the pid and time information. <br />
timer: set up timer and time interval upon module initialization; the timer reset itself inside the workqueue scheduler. The timer is deleted upon module exit<br />
workqueue: upon module initialization, create a single thread work queue, which will be executed by a single worker. schedule the function into the workqueue, and name it as mp1_proc.
Upon module exit, flush all unfinished work, and then destroy the work queue <br />
