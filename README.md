# putty_autologin
为putty增加自动登录功能  
add automatic login for putty  

# 如何编译how to compling
* 调试for test & debug  
`go mod tidy && go fmt && go build`  
* 发布for product  
`go mod tidy && go fmt && go build -ldflags "-w -s -H windowsgui" && upx -9 putty_autologin.exe`  
* 关于如何在Linux下编译，请参考我的另一个repository[跳转到](https://github.com/elitah/webvnc/tree/main/docker)

# 修改图标modify logo
* 安装rsrc  
`GOARCH= GOOS= go get github.com/akavel/rsrc`  
* 创建syso  
`rsrc -manifest main.manifest -ico icon.ico -o main.syso`  
