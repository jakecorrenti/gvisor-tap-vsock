package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/net/stdio"
	"github.com/containers/gvisor-tap-vsock/pkg/sshclient"
	"github.com/containers/gvisor-tap-vsock/pkg/transport"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/containers/gvisor-tap-vsock/pkg/virtualnetwork"
	"github.com/dustin/go-humanize"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

var (
	debug           bool
	mtu             int
	endpoints       types.ArrayFlags
	vpnkitSocket    string
	qemuSocket      string
	bessSocket      string
	stdioSocket     string
	vfkitSocket     string
	forwardSocket   types.ArrayFlags
	forwardDest     types.ArrayFlags
	forwardUser     types.ArrayFlags
	forwardIdentity types.ArrayFlags
	sshPort         int
	pidFile         string
	exitCode        int
)

const (
	gatewayIP   = "192.168.127.1"
	sshHostPort = "192.168.127.2:22"
	hostIP      = "192.168.127.254"
	host        = "host"
	gateway     = "gateway"
)

func main() {
	flag.Var(&endpoints, "listen", "control endpoint")
	flag.BoolVar(&debug, "debug", false, "Print debug info")
	flag.IntVar(&mtu, "mtu", 1500, "Set the MTU")
	flag.IntVar(&sshPort, "ssh-port", 2222, "Port to access the guest virtual machine. Must be between 1024 and 65535")
	flag.StringVar(&vpnkitSocket, types.ListenVpnkit, "", "VPNKit socket to be used by Hyperkit")
	flag.StringVar(&qemuSocket, types.ListenQemu, "", "Socket to be used by Qemu")
	flag.StringVar(&bessSocket, types.ListenBess, "", "unixpacket socket to be used by Bess-compatible applications")
	flag.StringVar(&stdioSocket, types.ListenStdio, "", "accept stdio pipe")
	flag.StringVar(&vfkitSocket, types.ListenVfkit, "", "unixgram socket to be used by vfkit-compatible applications")
	flag.Var(&forwardSocket, "forward-sock", "Forwards a unix socket to the guest virtual machine over SSH")
	flag.Var(&forwardDest, "forward-dest", "Forwards a unix socket to the guest virtual machine over SSH")
	flag.Var(&forwardUser, "forward-user", "SSH user to use for unix socket forward")
	flag.Var(&forwardIdentity, "forward-identity", "Path to SSH identity key for forwarding")
	flag.StringVar(&pidFile, "pid-file", "", "Generate a file with the PID in it")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	// Make this the last defer statement in the stack
	defer os.Exit(exitCode)

	groupErrs, ctx := errgroup.WithContext(ctx)
	// Setup signal channel for catching user signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	if debug {
		log.SetLevel(log.DebugLevel)
	}

	config := types.NewConfiguration()
	config.Debug = debug
	config.CaptureFile = captureFile()
	config.MTU = mtu
	config.GatewayIP = gatewayIP
	config.DNS = []types.Zone{
		{
			Name: "containers.internal.",
			Records: []types.Record{
				{
					Name: gateway,
					IP:   net.ParseIP(gatewayIP),
				},
				{
					Name: host,
					IP:   net.ParseIP(hostIP),
				},
			},
		},
		{
			Name: "docker.internal.",
			Records: []types.Record{
				{
					Name: gateway,
					IP:   net.ParseIP(gatewayIP),
				},
				{
					Name: host,
					IP:   net.ParseIP(hostIP),
				},
			},
		},
	}
	config.NAT = map[string]string{
		hostIP: "127.0.0.1",
	}
	config.GatewayVirtualIPs = []string{hostIP}
	config.Endpoints = endpoints

	sockets := map[string]string{
		types.ListenVpnkit: vpnkitSocket,
		types.ListenQemu:   qemuSocket,
		types.ListenBess:   bessSocket,
		types.ListenStdio:  stdioSocket,
		types.ListenVfkit:  vfkitSocket,
	}

	if err := config.AddSocketsFromCmdline(sockets); err != nil {
		exitWithError(err)
	}

	// If the given port is not between the privileged ports
	// and the oft considered maximum port, return an error.
	if sshPort < 1024 || sshPort > 65535 {
		exitWithError(errors.New("ssh-port value must be between 1024 and 65535"))
	}
	config.Forwards = map[string]string{
		fmt.Sprintf("127.0.0.1:%d", sshPort): sshHostPort,
	}

	config.SetProtocol()

	forwardInfo := map[string]types.ArrayFlags{
		types.ForwardSocket:   forwardSocket,
		types.ForwardDest:     forwardDest,
		types.ForwardUser:     forwardUser,
		types.ForwardIdentity: forwardIdentity,
	}

	if err := config.AddForwardInfoFromCmdline(forwardInfo); err != nil {
		exitWithError(err)
	}

	// Create a PID file if requested
	if len(pidFile) > 0 {
		f, err := os.Create(pidFile)
		if err != nil {
			exitWithError(err)
		}
		// Remove the pid-file when exiting
		defer func() {
			if err := os.Remove(pidFile); err != nil {
				log.Error(err)
			}
		}()
		pid := os.Getpid()
		if _, err := f.WriteString(strconv.Itoa(pid)); err != nil {
			exitWithError(err)
		}

		config.Pidfile = pidFile
	}

	groupErrs.Go(func() error {
		return run(ctx, groupErrs, &config)
	})

	// Wait for something to happen
	groupErrs.Go(func() error {
		select {
		// Catch signals so exits are graceful and defers can run
		case <-sigChan:
			cancel()
			return errors.New("signal caught")
		case <-ctx.Done():
			return nil
		}
	})
	// Wait for all of the go funcs to finish up
	if err := groupErrs.Wait(); err != nil {
		log.Error(err)
		exitCode = 1
	}
}

func captureFile() string {
	if !debug {
		return ""
	}
	return "capture.pcap"
}

func run(ctx context.Context, g *errgroup.Group, configuration *types.Configuration) error {
	vn, err := virtualnetwork.New(configuration)
	if err != nil {
		return err
	}
	log.Info("waiting for clients...")

	for _, endpoint := range configuration.Endpoints {
		log.Infof("listening %s", endpoint)
		ln, err := transport.Listen(endpoint)
		if err != nil {
			return errors.Wrap(err, "cannot listen")
		}
		httpServe(ctx, g, ln, withProfiler(vn))
	}

	ln, err := vn.Listen("tcp", fmt.Sprintf("%s:80", gatewayIP))
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/services/forwarder/all", vn.Mux())
	mux.Handle("/services/forwarder/expose", vn.Mux())
	mux.Handle("/services/forwarder/unexpose", vn.Mux())
	httpServe(ctx, g, ln, mux)

	if debug {
		g.Go(func() error {
		debugLog:
			for {
				select {
				case <-time.After(5 * time.Second):
					log.Debugf("%v sent to the VM, %v received from the VM\n", humanize.Bytes(vn.BytesSent()), humanize.Bytes(vn.BytesReceived()))
				case <-ctx.Done():
					break debugLog
				}
			}
			return nil
		})
	}

	if vpnkitSocket != "" {
		vpnkitListener, err := transport.Listen(vpnkitSocket)
		if err != nil {
			return err
		}
		g.Go(func() error {
		vpnloop:
			for {
				select {
				case <-ctx.Done():
					break vpnloop
				default:
					// pass through
				}
				conn, err := vpnkitListener.Accept()
				if err != nil {
					log.Errorf("vpnkit accept error: %s", err)
					continue
				}
				g.Go(func() error {
					return vn.AcceptVpnKit(conn)
				})
			}
			return nil
		})
	}

	if qemuSocket != "" {
		qemuListener, err := transport.Listen(qemuSocket)
		if err != nil {
			return err
		}

		g.Go(func() error {
			<-ctx.Done()
			if err := qemuListener.Close(); err != nil {
				log.Errorf("error closing %s: %q", qemuSocket, err)
			}
			return os.Remove(qemuSocket)
		})

		g.Go(func() error {
			conn, err := qemuListener.Accept()
			if err != nil {
				return errors.Wrap(err, "qemu accept error")

			}
			return vn.AcceptQemu(ctx, conn)
		})
	}

	if bessSocket != "" {
		bessListener, err := transport.Listen(bessSocket)
		if err != nil {
			return err
		}

		g.Go(func() error {
			<-ctx.Done()
			if err := bessListener.Close(); err != nil {
				log.Errorf("error closing %s: %q", bessSocket, err)
			}
			return os.Remove(bessSocket)
		})

		g.Go(func() error {
			conn, err := bessListener.Accept()
			if err != nil {
				return errors.Wrap(err, "bess accept error")

			}
			return vn.AcceptBess(ctx, conn)
		})
	}

	if vfkitSocket != "" {
		conn, err := transport.ListenUnixgram(vfkitSocket)
		if err != nil {
			return err
		}

		g.Go(func() error {
			<-ctx.Done()
			if err := conn.Close(); err != nil {
				log.Errorf("error closing %s: %q", vfkitSocket, err)
			}
			return os.Remove(vfkitSocket)
		})

		g.Go(func() error {
			vfkitConn, err := transport.AcceptVfkit(conn)
			if err != nil {
				return err
			}
			return vn.AcceptVfkit(ctx, vfkitConn)
		})
	}

	if stdioSocket != "" {
		g.Go(func() error {
			conn := stdio.GetStdioConn()
			return vn.AcceptStdio(ctx, conn)
		})
	}

	for i := 0; i < len(forwardSocket); i++ {
		var (
			src *url.URL
			err error
		)
		if strings.Contains(forwardSocket[i], "://") {
			src, err = url.Parse(forwardSocket[i])
			if err != nil {
				return err
			}
		} else {
			src = &url.URL{
				Scheme: "unix",
				Path:   forwardSocket[i],
			}
		}

		dest := &url.URL{
			Scheme: "ssh",
			User:   url.User(forwardUser[i]),
			Host:   sshHostPort,
			Path:   forwardDest[i],
		}
		j := i
		g.Go(func() error {
			defer os.Remove(forwardSocket[j])
			forward, err := sshclient.CreateSSHForward(ctx, src, dest, forwardIdentity[j], vn)
			if err != nil {
				return err
			}
			go func() {
				<-ctx.Done()
				// Abort pending accepts
				forward.Close()
			}()
		loop:
			for {
				select {
				case <-ctx.Done():
					break loop
				default:
					// proceed
				}
				err := forward.AcceptAndTunnel(ctx)
				if err != nil {
					log.Debugf("Error occurred handling ssh forwarded connection: %q", err)
				}
			}
			return nil
		})
	}

	return nil
}

func httpServe(ctx context.Context, g *errgroup.Group, ln net.Listener, mux http.Handler) {
	g.Go(func() error {
		<-ctx.Done()
		return ln.Close()
	})
	g.Go(func() error {
		s := &http.Server{
			Handler:      mux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		}
		err := s.Serve(ln)
		if err != nil {
			if err != http.ErrServerClosed {
				return err
			}
			return err
		}
		return nil
	})
}

func withProfiler(vn *virtualnetwork.VirtualNetwork) http.Handler {
	mux := vn.Mux()
	if debug {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	}
	return mux
}

func exitWithError(err error) {
	log.Error(err)
	os.Exit(1)
}
