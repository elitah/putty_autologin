# putty_autologin
为putty增加自动登录功能  
add automatic login for putty  

# 如何编译how to compling
* 调试for test & debug  
`go mod tidy && go fmt && go build`  
* 发布for product  
`go mod tidy && go fmt && go build -ldflags "-w -s -H windowsgui" && upx -9 putty_autologin.exe`  
* 关于如何在Linux下编译，请参考我的另一个repository，请通过以下链接打开页面，然后参考段落“编译方法”进行操作
`https://github.com/elitah/webvnc#%E7%BC%96%E8%AF%91%E6%96%B9%E6%B3%95`

# 修改图标modify logo
* 安装rsrc  
`GOARCH= GOOS= go get github.com/akavel/rsrc`  
* 创建syso  
`rsrc -manifest main.manifest -ico icon.ico -o main.syso`  
