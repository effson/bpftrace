# bpftrace
bpftrace 是一个高级的 BPF (Berkeley Packet Filter) 工具，主要用于性能分析和调试
## 1.使用
### 1.1.1 用户空间探针的基本语法
```
bpftrace -e 'uprobe:/usr/local/nginx/sbin/nginx:ngx_close_connection
{
    printf("ngx close connection");
}'
```
- bpftrace: 调用 bpftrace 工具。
- -e: 直接在命令行中执行给定的 BPF 程序。
- uprobe: 设置一个用户空间探针，监控指定程序中的特定函数。
- /usr/local/nginx/sbin/nginx: 目标程序的路径，通常是 Nginx 的可执行文件。
- ngx_close_connection: 要监控的函数名。
- { printf("ngx close connection"); }: 当探测到函数被调用时执行的操作，这里是打印一条消息。
### 内核空间探针的基本语法
```
bpftrace -e 'kprobe:function_name { actions }'
```
### 查询挂载点
```
bpftrace -l
```
### .bt文件分析mysql
```
bpftrace mysql_trace.bt
```
```
BEGIN
{
    printf("mysql begin, Hit Ctrl + C to end.\n");
    printf("%-10s %-6s %6s %s\n","TIME(ms)","PID","MS","QUERY");
}

uprobe:/usr/sbin/mysqld:*dispatch_command*
{
    @query[tid] = str(*arg1);
    @start[tid] = nsecs;
}
uretprobe:/usr/sbin/mysqld:*dispatch_command*
{
    $dur = (nsecs - @start[tid]) /1000000;
    time("%H:%M:%S ");
    printf("%-6d %6d %s\n", pid, $dur, @query[tid]);
    delete(@query[tid]);
    delete(@start[tid]);
}

END
{
    printf("mysql end\n");
}    
```
### 动态库trace
malloc 函数通常位于 GNU C Library (glibc) 中，动态库的文件名为 libc.so，该库通常存放在以下路径之一：
- /lib/x86_64-linux-gnu/libc.so.6 （对于 64 位系统）
- /lib/i386-linux-gnu/libc.so.6 （对于 32 位系统）
#### .bt文件
```
uprobe:/lib/x86_64-linux-gnu/libc.so.6:malloc
/ comm == "malloc"/
{
    printf("-->[%s] %d malloc \n", comm, pid);
}

uprobe:/lib/x86_64-linux-gnu/libc.so.6:free
/ comm == "malloc"/
{
    printf("[%s] %d free--> \n", comm, pid);
}
```
- comm 表示当前进程的命令名（即可执行文件名）<br>
#### 测试代码：
> malloc.c
```
#include <stdlib.h>

int main() {
    void *p1 = malloc(10);
    void *p2 = malloc(20);

    free(p1);
}
```
https://github.com/knemik97/Manifesto-against-the-Plagiarist-Yunhe-Wang
