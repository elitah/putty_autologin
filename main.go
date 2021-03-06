package main

import (
	_ "embed"

	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/elitah/fast-io"

	"github.com/lxn/win"

	"github.com/elazarl/goproxy"
	"github.com/lxn/walk"
	"github.com/lxn/walk/declarative"
	"golang.org/x/sys/windows/registry"
)

//go:embed _putty.exe
var putty []byte

var (
	mu sync.Mutex

	hKernel32 uintptr

	puttyPath string

	tlsCfg *tls.Config

	proxyMsg = `已开启HTTP代理服务器，请使用%s:%d进行连接

Linux环境请设置环境变量：
export http_proxy=http://%s:%d

如果您的设备不支持https连接，可使用前缀
http://https2http/
进行代理连接

例如访问https://www.baidu.com/
只需将https://替换为http://https2http/即可
（即http://http2http/www.baidu.com/）
`
)

func init() {
	//
	if h, err := syscall.LoadLibrary("kernel32.dll"); nil == err {
		//
		atomic.StoreUintptr(&hKernel32, uintptr(h))
	} else {
		//
		fmt.Println(err)
	}
	//
	if key, err := rsa.GenerateKey(rand.Reader, 2048); nil == err {
		//
		template := x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "http proxy",
			},
			NotBefore: time.Now(),
			NotAfter:  time.Date(2099, time.December, 31, 15, 59, 59, 1e9-1, time.UTC),

			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,

			DNSNames: []string{"*"},
		}
		//
		if data, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key); nil == err {
			//
			out1, out2 := &bytes.Buffer{}, &bytes.Buffer{}
			//
			pem.Encode(
				out1,
				&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: data,
				},
			)
			//
			pem.Encode(
				out2,
				&pem.Block{
					Type:  "RSA PRIVATE KEY",
					Bytes: x509.MarshalPKCS1PrivateKey(key),
				},
			)
			//
			if c, err := tls.X509KeyPair(out1.Bytes(), out2.Bytes()); nil == err {
				//
				tlsCfg = &tls.Config{
					Certificates: []tls.Certificate{
						c,
					},
				}
			} else {
				//
				fmt.Println(err)
			}
		} else {
			//
			fmt.Println(err)
		}
	} else {
		//
		fmt.Println(err)
	}
}

func loadKernel32() (syscall.Handle, error) {
	//
	if p := atomic.LoadUintptr(&hKernel32); 0 != p {
		//
		return syscall.Handle(p), nil
	} else {
		//
		return syscall.Handle(0), fmt.Errorf("no such library")
	}
}

func lockFile(fd uintptr) (ret bool) {
	//
	if h, err := loadKernel32(); nil == err {
		//
		if addr, err := syscall.GetProcAddress(h, "LockFile"); nil == err {
			//
			r0, _, _ := syscall.Syscall6(addr, 5, fd, 0, 0, 0, 1, 0)
			//
			ret = 0 != int(r0)
		}
	}
	//
	return ret
}

func testFileIsLocked(path string) (ret bool) {
	//
	if f, err := os.Open(path); nil == err {
		//
		ret = !lockFile(f.Fd())
		//
		f.Close()
	}
	//
	return
}

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
					if !testFileIsLocked(item) {
						//
						os.Remove(item)
					}
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

func setTCPSmart(conns ...net.Conn) {
	//
	for i, _ := range conns {
		//
		if _conn, ok := conns[i].(*net.TCPConn); ok {
			//
			_conn.SetNoDelay(true)
			//
			_conn.SetReadBuffer(0)
			_conn.SetWriteBuffer(0)
		}
	}
}

func submitUsernameAndPassword(conn, tconn net.Conn, username, password string) bool {
	//
	var buffer [1024]byte
	//
	defer conn.SetReadDeadline(time.Time{})
	//
	for {
		//
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		//
		if n, err := conn.Read(buffer[:]); nil == err {
			//
			tconn.Write(buffer[:n])
			//
			if strings.HasSuffix(string(buffer[:n]), "ogin: ") {
				//
				conn.Write([]byte(username + "\n"))
			} else if strings.HasSuffix(string(buffer[:n]), "assword: ") {
				//
				conn.Write([]byte(password + "\n"))
				//
				return true
			}
		} else {
			//
			return false
		}
	}
}

func startConnectToSSH(mw *walk.MainWindow, ok chan struct{}, address, username, password string, ip ...*string) {
	//
	if conn, err := net.DialTimeout("tcp4", address, 5*time.Second); nil == err {
		//
		var remote string
		//
		var port int
		//
		if 0 < len(ip) && nil != ip[0] {
			//
			if addr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
				//
				*ip[0] = addr.IP.String()
			}
		}
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
				"putty",
				"-load", "putty_autologin",
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

func startConnectToTelnet(mw *walk.MainWindow, ok chan struct{}, address, username, password string, ip ...*string) {
	//
	if conn, err := net.DialTimeout("tcp4", address, 5*time.Second); nil == err {
		//
		if 0 < len(ip) && nil != ip[0] {
			//
			if addr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
				//
				*ip[0] = addr.IP.String()
			}
		}
		//
		conn.Close()
		//
		if l, err := net.Listen("tcp4", "127.0.0.1:0"); nil == err {
			//
			var port int
			//
			var wg sync.WaitGroup
			//
			if addr, ok := l.Addr().(*net.TCPAddr); ok {
				//
				port = addr.Port
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
								setTCPSmart(local, remote)
								//
								if submitUsernameAndPassword(remote, local, username, password) {
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
					"-load", "putty_autologin",
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

func startConnectTo(mw *walk.MainWindow, ok chan struct{}, ssh bool, address, username, password string, ip ...*string) {
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
		startConnectToSSH(mw, ok, address, username, password, ip...)
	} else {
		//
		startConnectToTelnet(mw, ok, address, username, password, ip...)
	}
}

type wrapConn struct {
	sync.Mutex

	net.Conn

	b *bytes.Buffer

	f int32
}

func NewWrapConn(conn net.Conn, args ...int) *wrapConn {
	//
	size := 4 * 1024
	//
	for _, item := range args {
		//
		if 0 < item {
			//
			size = item
		}
	}
	//
	return &wrapConn{
		Conn: conn,
		b:    bytes.NewBuffer(make([]byte, 0, size)),
	}
}

func (this *wrapConn) PourOut() {
	//
	atomic.StoreInt32(&this.f, 0x1)
}

func (this *wrapConn) Read(p []byte) (n int, err error) {
	//
	if 0x0 == atomic.LoadInt32(&this.f) {
		//
		n, err = this.Conn.Read(p)
		//
		if 0 < n {
			//
			this.b.Write(p[:n])
		}
	} else {
		//
		this.Lock()
		defer this.Unlock()
		//
		if nil == this.b {
			//
			n, err = this.Conn.Read(p)
		} else {
			//
			n, err = this.b.Read(p)
			//
			if err == io.EOF {
				//
				var _n int
				//
				this.b = nil
				//
				_n, err = this.Conn.Read(p[n:])
				//
				n += _n
			}
		}
	}
	//
	return
}

func (this *wrapConn) Close() error {
	//
	return this.Conn.Close()
}

type muxListener struct {
	net.Listener

	c chan net.Conn

	err error
}

func (this *muxListener) Accept() (net.Conn, error) {
	//
	for conn := range this.c {
		//
		return conn, nil
	}
	//
	return nil, this.err
}

func (this *muxListener) handshake(conn net.Conn) {
	//
	wconn := NewWrapConn(conn)
	//
	sconn := tls.Server(wconn, tlsCfg)
	//
	if err := sconn.Handshake(); nil == err {
		//
		this.c <- sconn
	} else if _, ok := err.(tls.RecordHeaderError); ok {
		//
		wconn.PourOut()
		//
		this.c <- wconn
	} else {
		//
		fmt.Printf("%T, %v\n", err, err)
		//
		sconn.Close()
	}
}

func (this *muxListener) loop() {
	//
	for {
		//
		if conn, err := this.Listener.Accept(); nil == err {
			//
			go this.handshake(conn)
		} else {
			//
			this.err = err
			//
			close(this.c)
			//
			return
		}
	}
}

func main() {
	//
	const WINDOW_HEIGHT = 100
	const WINDOW_WIDTH = 200
	//
	var fLock *os.File
	//
	var mw *walk.MainWindow
	//
	var inLE1, inLE2, inLE3 *walk.LineEdit
	//
	var chkbox, chkbox1 *walk.CheckBox
	//
	var btnCC *walk.PushButton
	//
	var ls net.Listener
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
			declarative.Label{Text: "其他选项:"},
			declarative.CheckBox{
				AssignTo: &chkbox1,
				Text:     "启动HTTP代理服务器                 ",
				OnCheckedChanged: func() {
					//
					if chkbox1.Checked() {
						//
					} else {
						//
					}
				},
			},
			declarative.PushButton{
				AssignTo: &btnCC,
				Text:     "开始连接",
				OnClicked: func() {
					//
					var ip string
					//
					ok := make(chan struct{})
					//
					btnCC.SetEnabled(false)
					//
					if key, _, err := registry.CreateKey(registry.CURRENT_USER, "Software\\SimonTatham\\PuTTY\\Sessions\\putty_autologin", registry.ALL_ACCESS); nil == err {
						//
						key.SetDWordValue("CloseOnExit", 0x0)
						key.SetStringValue("WinTitle", inLE1.Text())
					}
					//
					go startConnectTo(mw, ok, chkbox.Checked(), inLE1.Text(), inLE2.Text(), inLE3.Text(), &ip)
					//
					go func() {
						//
						<-ok
						//
						btnCC.SetEnabled(true)
						//
						if chkbox1.Checked() {
							//
							if nil == ls {
								//
								if l, err := net.Listen("tcp4", ":0"); nil == err {
									//
									ls = l
								}
							}
							//
							if nil != ls {
								//
								if addr, ok := ls.Addr().(*net.TCPAddr); ok {
									//
									go func(l net.Listener) {
										//
										proxy := goproxy.NewProxyHttpServer()
										//
										proxy.OnRequest(
											goproxy.DstHostIs("https2http"),
										).DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
											//
											switch r.URL.Path {
											case "/":
											case "/favicon.ico":
												//
												return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusNotFound, "Not Found")
											default:
												//
												ss := strings.SplitN(r.URL.Path[1:], "/", 2)
												//
												if n := len(ss); 1 <= n {
													//
													u := url.URL{
														Scheme:   "https",
														User:     r.URL.User,
														Host:     ss[0],
														RawQuery: r.URL.RawQuery,
														Fragment: r.URL.Fragment,
													}
													//
													if 2 <= n && "" != ss[1] {
														//
														u.Path = ss[1]
													} else {
														//
														u.Path = "/"
													}
													//
													if req, err := http.NewRequest(r.Method, u.String(), r.Body); nil == err {
														//
														for key, values := range r.Header {
															//
															if "Host" == key {
																//
																continue
															}
															//
															for _, v := range values {
																//
																req.Header.Add(key, v)
															}
														}
														//
														if resp, err := http.DefaultClient.Do(req); nil == err {
															//
															return req, resp
														} else {
															//
															return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusBadGateway, err.Error())
														}
													} else {
														//
														return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusServiceUnavailable, err.Error())
													}
												}
											}
											//
											return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusBadRequest, "Unable get hostname from path")
										})
										//
										ll := &muxListener{
											Listener: l,
											c:        make(chan net.Conn),
										}
										//
										go ll.loop()
										//
										http.Serve(ll, proxy)
									}(ls)
									//
									walk.MsgBox(
										mw,
										"提示",
										fmt.Sprintf(
											proxyMsg,
											ip,
											addr.Port,
											ip,
											addr.Port,
										),
										walk.MsgBoxIconInformation,
									)
								} else {
									//
									ls.Close()
								}
							}
						}
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
	mw.SetVisible(true)
	//
	inLE1.SetText("192.168.88.88:23")
	inLE2.SetText("root")
	inLE3.SetText("Li$tpArp123?")
	//
	if path := getEmbedPath("exe"); "" != path {
		//
		if f, err := os.Open(path); nil == err {
			//
			if lockFile(f.Fd()) {
				//
				fLock = f
			} else {
				//
				f.Close()
			}
		}
	}
	//
	mw.Run()
	//
	if nil != fLock {
		//
		fLock.Close()
	}
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
