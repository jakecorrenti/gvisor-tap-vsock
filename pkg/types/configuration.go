package types

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	ListenVpnkit = "listen-vpnkit"
	ListenQemu   = "listen-qemu"
	ListenBess   = "liten-bess"
	ListenStdio  = "listen-stdio"
	ListenVfkit  = "listen-vfkit"

	ForwardSock     = "forward-sock"
	ForwardDest     = "forward-dest"
	ForwardUser     = "forward-user"
	ForwardIdentity = "forward-identity"
)

type Configuration struct {
	// Print packets on stderr
	Debug bool

	// Record all packets coming in and out in a file that can be read by Wireshark (pcap)
	CaptureFile string

	// Length of packet
	// Larger packets means less packets to exchange for the same amount of data (and less protocol overhead)
	MTU int

	// Network reserved for the virtual network
	Subnet string

	// IP address of the virtual gateway
	GatewayIP string

	// MAC address of the virtual gateway
	GatewayMacAddress string

	// Built-in DNS records that will be served by the DNS server embedded in the gateway
	DNS []Zone

	// List of search domains that will be added in all DHCP replies
	DNSSearchDomains []string

	// Port forwarding between the machine running the gateway and the virtual network.
	Forwards map[string]string

	// Address translation of incoming traffic.
	// Useful for reaching the host itself (localhost) from the virtual network.
	NAT map[string]string

	// IPs assigned to the gateway that can answer to ARP requests
	GatewayVirtualIPs []string

	// DHCP static leases. Allow to assign pre-defined IP to virtual machine based on the MAC address
	DHCPStaticLeases map[string]string

	// Only for Hyperkit
	// Allow to assign a pre-defined MAC address to an Hyperkit VM
	VpnKitUUIDMacAddresses map[string]string

	// Protocol to be used. Only for /connect mux
	Protocol Protocol

	// Sockets is a map of the sockets provided by the user with format socket-type:socket
	Sockets map[string]string

	// Endpoints maintains a list of endpoints the user would like to listen to
	Endpoints []string

	// Pidfile represents the pidfile where the user wanted to store the gvproxy pid
	Pidfile string

	// ForwardInfo maintains a map of the forward-xxx flag info from the commandline
	ForwardInfo map[string]ArrayFlags

	// SSHPort to access the guest virtual machine. Must be between 1024 and 65535 (default 2222)
	SSHPort int
}

type Protocol string

const (
	// HyperKitProtocol is handshake, then 16bits little endian size of packet, then the packet.
	HyperKitProtocol Protocol = "hyperkit"
	// QemuProtocol is 32bits big endian size of the packet, then the packet.
	QemuProtocol Protocol = "qemu"
	// BessProtocol transfers bare L2 packets as SOCK_SEQPACKET.
	BessProtocol Protocol = "bess"
	// StdioProtocol is HyperKitProtocol without the handshake
	StdioProtocol Protocol = "stdio"
	// VfkitProtocol transfers bare L2 packets as SOCK_DGRAM.
	VfkitProtocol Protocol = "vfkit"
)

type Zone struct {
	Name      string
	Records   []Record
	DefaultIP net.IP
}

type Record struct {
	Name   string
	IP     net.IP
	Regexp *regexp.Regexp
}

type ArrayFlags []string

func (i *ArrayFlags) String() string {
	return "my string representation"
}

func (i *ArrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

// NewConfiguration is a default contstructor for the Configuration type
func NewConfiguration() Configuration {
	return Configuration{
		Subnet:            "192.168.127.0/24",
		GatewayMacAddress: "5a:94:ef:e4:0c:dd",
		DHCPStaticLeases: map[string]string{
			"192.168.127.2": "5a:94:ef:e4:0c:ee",
		},
		DNSSearchDomains: searchDomains(),
		VpnKitUUIDMacAddresses: map[string]string{
			"c3d68012-0208-11ea-9fd7-f2189899ab08": "5a:94:ef:e4:0c:ee",
		},
	}
}

// validateQemuSocket makes sure the qemu socket provided has proper syntax
func validateQemuSocket(socket string) error {
	if len(socket) > 0 {
		uri, err := url.Parse(socket)
		if err != nil || uri == nil {
			return errors.Wrapf(err, "invalid value for listen-qemu")
		}
		if _, err := os.Stat(uri.Path); err == nil && uri.Scheme == "unix" {
			return errors.Errorf("%q already exists", uri.Path)
		}
	}
	return nil
}

// validateBessSocket makes sure the bess socket provided has proper syntax
func validateBessSocket(socket string) error {
	if len(socket) > 0 {
		uri, err := url.Parse(socket)
		if err != nil || uri == nil {
			return errors.Wrapf(err, "invalid value for listen-bess")
		}
		if uri.Scheme != "unixpacket" {
			return errors.New("listen-bess must be unixpacket:// address")
		}
		if _, err := os.Stat(uri.Path); err == nil {
			return errors.Errorf("%q already exists", uri.Path)
		}
	}
	return nil
}

// validateVfkitSocket makes sure the vfki socket provided has proper syntax
func validateVfkitSocket(socket string) error {
	if len(socket) > 0 {
		uri, err := url.Parse(socket)
		if err != nil || uri == nil {
			return errors.Wrapf(err, "invalid value for listen-vfkit")
		}
		if uri.Scheme != "unixgram" {
			return errors.New("listen-vfkit must be unixgram:// address")
		}
		if _, err := os.Stat(uri.Path); err == nil {
			return errors.Errorf("%q already exists", uri.Path)
		}
	}

	return nil
}

// validateOnlyUsingSingleProtocol ensures that we are only using one protocol
// at a time
func validateOnlyUsingSingleProtocol(vpnkitSocket, qemuSocket, bessSocket string) error {
	if vpnkitSocket != "" && qemuSocket != "" {
		return errors.New("cannot use qemu and vpnkit protocol at the same time")
	}
	if vpnkitSocket != "" && bessSocket != "" {
		return errors.New("cannot use bess and vpnkit protocol at the same time")
	}
	if qemuSocket != "" && bessSocket != "" {
		return errors.New("cannot use qemu and bess protocol at the same time")
	}
	return nil
}

// AddSocketsFromCmdline adds the different sockets to the Configuration based
// on the flags used in the commandline by the user
func (c *Configuration) AddSocketsFromCmdline(sockets map[string]string) error {
	var vpnkitSocket, qemuSocket, bessSocket string

	for flag, socket := range sockets {
		var err error
		switch flag {
		case ListenQemu:
			qemuSocket = socket
			err = validateQemuSocket(socket)
		case ListenBess:
			bessSocket = socket
			err = validateBessSocket(socket)
		case ListenVfkit:
			err = validateVfkitSocket(socket)
		case ListenVpnkit:
			vpnkitSocket = socket
		}

		if err != nil {
			return err
		}
	}

	if err := validateOnlyUsingSingleProtocol(vpnkitSocket, qemuSocket, bessSocket); err != nil {
		return err
	}

	c.Sockets = sockets
	return nil
}

func (c *Configuration) SetProtocol() {
	protocol := HyperKitProtocol
	qemuSocket, qemuOk := c.Sockets[ListenQemu]
	bessSocket, bessOk := c.Sockets[ListenBess]
	vfkitSocket, vfkitOk := c.Sockets[ListenVfkit]

	if qemuOk && qemuSocket != "" {
		protocol = QemuProtocol
	}
	if bessOk && bessSocket != "" {
		protocol = BessProtocol
	}
	if vfkitOk && vfkitSocket != "" {
		protocol = VfkitProtocol
	}

	c.Protocol = protocol
}

func (c *Configuration) AddForwardInfoFromCmdline(info map[string]ArrayFlags) error {
	if c := len(info[ForwardSock]); c != len(info[ForwardDest]) || c != len(info[ForwardUser]) || c != len(info[ForwardIdentity]) {
		return errors.New("-forward-sock, -forward-dest, -forward-user, and -forward-identity must all be specified together, " +
			"the same number of times, or not at all")
	}

	for i := 0; i < len(info[ForwardSock]); i++ {
		_, err := os.Stat(info[ForwardIdentity][i])
		if err != nil {
			return errors.Wrapf(err, "Identity file %s can't be loaded", info[ForwardIdentity][i])
		}
	}

	return nil
}

func (c *Configuration) ToCmdline() ([]string, error) {
	args := []string{}

	if c.Debug {
		args = append(args, "-debug")
	}

	// forward dest
	if forwardDest, ok := c.ForwardInfo[ForwardDest]; ok {
		for _, dest := range forwardDest {
			args = append(args, "-forward-dest "+dest)
		}
	}

	// forward identity
	if forwardIdentity, ok := c.ForwardInfo[ForwardIdentity]; ok {
		for _, identity := range forwardIdentity {
			args = append(args, "-forward-identity "+identity)
		}
	}

	// forward sock
	if forwardSock, ok := c.ForwardInfo[ForwardSock]; ok {
		for _, sock := range forwardSock {
			args = append(args, "-forward-sock "+sock)
		}
	}

	// forward user
	if forwardUser, ok := c.ForwardInfo[ForwardUser]; ok {
		for _, user := range forwardUser {
			args = append(args, "-forward-user "+user)
		}
	}

	// listen (endpoints)
	for _, endpoint := range c.Endpoints {
		args = append(args, "-listen "+endpoint)
	}

	// listen qemu
	if qemuSocket, ok := c.Sockets[ListenQemu]; ok {
		if qemuSocket != "" {
			args = append(args, "-listen-qemu "+qemuSocket)
		}
	}

	// listen stdio
	if stdioSocket, ok := c.Sockets[ListenStdio]; ok {
		if stdioSocket != "" {
			args = append(args, "-listen-stdio "+stdioSocket)
		}
	}

	// listen vfkit
	if vfkitSocket, ok := c.Sockets[ListenVfkit]; ok {
		if vfkitSocket != "" {
			args = append(args, "-listen-vfkit "+vfkitSocket)
		}
	}

	// listen vpnkit
	if vpnkitSocket, ok := c.Sockets[ListenVpnkit]; ok {
		if vpnkitSocket != "" {
			args = append(args, "-listen-vpnkit "+vpnkitSocket)
		}
	}

	// listen bess
	if bessSocket, ok := c.Sockets[ListenBess]; ok {
		if bessSocket != "" {
			args = append(args, "-listen-bess "+bessSocket)
		}
	}

	// mtu
	args = append(args, fmt.Sprintf("-mtu %d", c.MTU))

	// pidfile
	if c.Pidfile != "" {
		args = append(args, "-pid-file "+c.Pidfile)
	}

	// sshport
	args = append(args, fmt.Sprintf("-ssh-port %d", c.SSHPort))

	return args, nil
}

func (c *Configuration) Cmd(gvproxyPath string) (*exec.Cmd, error) {
	args, err := c.ToCmdline()
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(gvproxyPath, args...)
	return cmd, nil
}

func searchDomains() []string {
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		f, err := os.Open("/etc/resolv.conf")
		if err != nil {
			log.Errorf("open file error: %v", err)
			return nil
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		searchPrefix := "search "
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), searchPrefix) {
				searchDomains := strings.Split(strings.TrimPrefix(sc.Text(), searchPrefix), " ")
				log.Debugf("Using search domains: %v", searchDomains)
				return searchDomains
			}
		}
		if err := sc.Err(); err != nil {
			log.Errorf("scan file error: %v", err)
			return nil
		}
	}
	return nil
}
