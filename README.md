# gomodscan


## 使用说明
### 当前版本只支持go扫描，后续会逐步支持其他语言的漏洞扫描
```go
gomodscan scan --source-dir ./resource-scheduler
```

### 注意事项
需要保证当前目录下有db目录，目录中包括最新版本的trivy-db的数据库，通过读取数据库去查询当前的go.mod文件中是否存在漏洞