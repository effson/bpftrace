# bpftrace
bpftrace 是一个高级的 BPF (Berkeley Packet Filter) 工具，主要用于性能分析和调试
## 1.使用
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
