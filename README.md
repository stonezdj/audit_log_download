# tools to download audit log

## How to use


```
git clone https://github.com/stonezdj/audit_log_download
cd audit_log_download

go run .  --hostname=<harbor_hostname> -username=<username> -password=<password> -q=operation=delete,resource=~nginx,username=admin
```

