package dnsclt

import (
	"fmt"
	"net/netip"
	"sync/atomic"

	"github.com/andrewz1/xtoml"
	"github.com/miekg/dns"
)

const (
	dnsPort = 53
)

type Conf struct {
	UpLinks []string `conf:"dns.uplink,required"`

	ul  []string
	num atomic.Uint32
	cl  *dns.Client
}

var (
	opt = &Conf{}
)

func Init(xc *xtoml.XConf) error {
	err := xc.LoadConf(opt)
	if err != nil {
		return err
	}
	opt.ul = make([]string, 0, len(opt.UpLinks))
	var va string
	for _, a := range opt.UpLinks {
		if va, err = verifyAddr(a); err != nil {
			return err
		}
		opt.ul = append(opt.ul, va)
	}
	opt.cl = &dns.Client{Net: "udp", UDPSize: 4096}
	return nil
}

func verifyAddr(addr string) (string, error) {
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return ap.String(), nil
	}
	if a, err := netip.ParseAddr(addr); err == nil {
		return netip.AddrPortFrom(a, dnsPort).String(), nil
	}
	return "", fmt.Errorf("invalid address %s", addr)
}

func nextServer() string {
	l := uint32(len(opt.ul))
	if l == 1 {
		return opt.ul[0]
	}
	n := opt.num.Add(1) % l
	return opt.ul[n]
}

func Resolve(m *dns.Msg) (*dns.Msg, error) {
	r, _, err := opt.cl.Exchange(m, nextServer())
	if err != nil {
		return nil, err
	}
	return r, nil
}
