# bpftrace
bpftrace 是一个高级的 BPF (Berkeley Packet Filter) 工具，主要用于性能分析和调试
## 1.使用
```
bpftrace -e 'uprobe:/usr/local/nginx/sbin/nginx:ngx_close_connection
{
    printf("ngx close connection");
}'
```
