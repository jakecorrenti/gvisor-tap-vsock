package types

import (
	"net"
	"net/url"
	"os"
	"regexp"

	"github.com/pkg/errors"
)

const (
	ListenVpnkit = "listen-vpnkit"
	ListenQemu   = "listen-qemu"
	ListenBess   = "liten-bess"
	ListenStdio  = "listen-stdio"
	ListenVfkit  = "listen-vfkit"
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
