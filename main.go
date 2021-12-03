package main

import (
	_ "embed"

	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/elitah/fast-io"

	"github.com/lxn/win"

	"github.com/lxn/walk"
	"github.com/lxn/walk/declarative"
)

//go:embed _putty.exe
var putty []byte

var (
	mu sync.Mutex

	puttyPath string
)

func getEmbedPath(format string) string {
	//
	var embedPath *string
	//
	switch format {
	case "exe":
		//
		embedPath = &puttyPath
	default:
		//
		return ""
	}
	//
	filename := fmt.Sprintf("putty.*.%s", format)
	//
	mu.Lock()
	defer mu.Unlock()
	//
	if "" == *embedPath {
		//
		if f, err := os.CreateTemp("", filename); nil == err {
			//
			_filename := f.Name()
			//
			f.Close()
			//
			if list, err := filepath.Glob(filepath.Join(filepath.Dir(_filename), filename)); nil == err {
				//
				for _, item := range list {
					//
					os.Remove(item)
				}
			}
		}
		if f, err := os.CreateTemp("", filename); nil == err {
			//
			f.Truncate(0)
			//
			f.Seek(0, os.SEEK_SET)
			//
			switch format {
			case "exe":
				//
				f.Write(putty)
			default:
				//
				return ""
			}
			//
			*embedPath = filepath.Join(f.Name())
			//
			f.Close()
		}
	}
	//
	return *embedPath
}

func submitUsernameAndPassword(conn net.Conn, username, password string) bool {
	//
	br := bufio.NewReader(conn)
	//
	defer conn.SetReadDeadline(time.Time{})
	//
	username = fmt.Sprintf("%s\n", username)
	password = fmt.Sprintf("%s\n", password)
	//
	for {
		//
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		//
		if data, err := br.ReadSlice(0x20); nil == err {
			//
			if strings.HasSuffix(string(data), "ogin: ") {
				//
				conn.Write([]byte(username))
			} else if strings.HasSuffix(string(data), "assword: ") {
				//
				conn.Write([]byte(password))
				//
				return true
			}
		} else {
			//
			return false
		}
	}
}

func startConnectToSSH(mw *walk.MainWindow, ok chan struct{}, address, username, password string) {
	//
	if conn, err := net.DialTimeout("tcp4", address, 5*time.Second); nil == err {
		//
		var remote string
		//
		var port int
		//
		if v := conn.RemoteAddr(); nil != v {
			//
			if addr, ok := v.(*net.TCPAddr); ok {
				//
				remote = addr.IP.String()
				//
				port = addr.Port
			}
		}
		//
		close(ok)
		//
		if p, err := os.StartProcess(
			filepath.Base(getEmbedPath("exe")),
			[]string{
				"-ssh",
				"-l", username,
				"-pw", password,
				"-P", fmt.Sprint(port),
				remote,
			},
			&os.ProcAttr{
				Dir:   os.Getenv("TEMP"),
				Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
			},
		); nil == err {
			//
			p.Wait()
		} else {
			//
			walk.MsgBox(mw, "错误", err.Error(), walk.MsgBoxIconError)
		}
		//
		return
	} else {
		//
		walk.MsgBox(mw, "错误", err.Error(), walk.MsgBoxIconError)
	}
	//
	close(ok)
}

func startConnectToTelnet(mw *walk.MainWindow, ok chan struct{}, address, username, password string) {
	//
	if conn, err := net.DialTimeout("tcp4", address, 5*time.Second); nil == err {
		//
		conn.Close()
		//
		if l, err := net.Listen("tcp4", "127.0.0.1:0"); nil == err {
			//
			var port int
			//
			var wg sync.WaitGroup
			//
			if v := l.Addr(); nil != v {
				//
				if addr, ok := v.(*net.TCPAddr); ok {
					//
					port = addr.Port
				}
			}
			//
			go func(wg *sync.WaitGroup, l net.Listener) {
				//
				for {
					//
					if conn, err := l.Accept(); nil == err {
						//
						wg.Add(1)
						//
						go func(wg *sync.WaitGroup, local net.Conn) {
							//
							defer wg.Done()
							//
							if remote, err := net.DialTimeout("tcp4", address, 5*time.Second); nil == err {
								//
								if submitUsernameAndPassword(remote, username, password) {
									//
									fast_io.FastCopy(local, remote)
								}
								//
								remote.Close()
							}
							//
							local.Close()
						}(wg, conn)
					} else {
						//
						break
					}
				}
			}(&wg, l)
			//
			close(ok)
			//
			if p, err := os.StartProcess(
				filepath.Base(getEmbedPath("exe")),
				[]string{
					"putty",
					"-telnet",
					"-P", fmt.Sprint(port),
					"127.0.0.1",
				},
				&os.ProcAttr{
					Dir:   os.Getenv("TEMP"),
					Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
				},
			); nil == err {
				//
				p.Wait()
			} else {
				//
				walk.MsgBox(mw, "错误", err.Error(), walk.MsgBoxIconError)
			}
			//
			wg.Wait()
			//
			l.Close()
			//
			return
		} else {
			//
			walk.MsgBox(mw, "错误", err.Error(), walk.MsgBoxIconError)
		}
	} else {
		//
		walk.MsgBox(mw, "错误", err.Error(), walk.MsgBoxIconError)
	}
	//
	close(ok)
}

func startConnectTo(mw *walk.MainWindow, ok chan struct{}, ssh bool, address, username, password string) {
	//
	host, port, _ := net.SplitHostPort(address)
	//
	if "" == port {
		//
		if ssh {
			//
			address = fmt.Sprintf("%s:22", address)
		} else {
			//
			address = fmt.Sprintf("%s:23", address)
		}
	} else if "" != host {
		//
		address = fmt.Sprintf("%s:%s", host, port)
	}
	//
	if ssh {
		//
		startConnectToSSH(mw, ok, address, username, password)
	} else {
		//
		startConnectToTelnet(mw, ok, address, username, password)
	}
}

func main() {
	//
	const WINDOW_HEIGHT = 100
	const WINDOW_WIDTH = 200
	//
	var mw *walk.MainWindow
	//
	var inLE1, inLE2, inLE3 *walk.LineEdit
	//
	var chkbox *walk.CheckBox
	//
	var btnCC *walk.PushButton
	//
	declarative.MainWindow{
		AssignTo: &mw,
		Title:    "putty(telnet)",
		Layout:   declarative.VBox{},
		Visible:  false,
		Children: []declarative.Widget{
			declarative.Label{Text: "请输入IP:Port:"},
			declarative.LineEdit{AssignTo: &inLE1},
			declarative.Label{Text: "请输入用户名:"},
			declarative.LineEdit{AssignTo: &inLE2},
			declarative.Label{Text: "请输入密码:"},
			declarative.LineEdit{
				AssignTo:     &inLE3,
				PasswordMode: true,
			},
			declarative.Label{Text: "请选择协议:"},
			declarative.CheckBox{
				AssignTo: &chkbox,
				Text:     "使用ssh协议(不勾选默认telnet)",
				OnCheckedChanged: func() {
					//
					if chkbox.Checked() {
						//
						mw.SetTitle("putty(ssh)")
					} else {
						//
						mw.SetTitle("putty(telnet)")
					}
				},
			},
			declarative.PushButton{
				AssignTo: &btnCC,
				Text:     "开始连接",
				OnClicked: func() {
					//
					ok := make(chan struct{})
					//
					btnCC.SetEnabled(false)
					//
					go startConnectTo(mw, ok, chkbox.Checked(), inLE1.Text(), inLE2.Text(), inLE3.Text())
					//
					go func() {
						//
						<-ok
						//
						btnCC.SetEnabled(true)
					}()
				},
			},
		},
	}.Create()
	//
	win.SetWindowLong(
		mw.Handle(),
		win.GWL_STYLE,
		(win.GetWindowLong(mw.Handle(), win.GWL_STYLE)|win.WS_OVERLAPPED) & ^win.WS_MINIMIZEBOX & ^win.WS_MAXIMIZEBOX & ^win.WS_THICKFRAME,
	)
	//
	mw.SetBounds(walk.Rectangle{
		X:      int((win.GetSystemMetrics(win.SM_CXSCREEN) - WINDOW_WIDTH) / 2),
		Y:      int((win.GetSystemMetrics(win.SM_CYSCREEN) - WINDOW_HEIGHT) / 2),
		Width:  WINDOW_WIDTH,
		Height: WINDOW_HEIGHT,
	})
	//
	if icon, err := walk.NewIconFromResourceId(3); nil == err {
		//
		mw.SetIcon(icon)
	} else {
		//
		fmt.Println(err)
	}
	//
	mw.SetVisible(true)
	//
	inLE1.SetText("192.168.88.88:23")
	inLE2.SetText("root")
	inLE3.SetText("Li$tpArp123?")
	//
	mw.Run()
	//
	mu.Lock()
	//
	if "" != puttyPath {
		//
		os.Remove(puttyPath)
	}
	//
	mu.Unlock()
}
