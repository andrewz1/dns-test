package dnssrv

import (
	"bufio"
	"net"
	"os"
	"sync"

	"github.com/andrewz1/xlog"
	"github.com/andrewz1/xtoml"
	"github.com/miekg/dns"

	"github.com/andrewz1/dns-test/dnsclt"
)

type Conf struct {
	Listen  []string `conf:"dns.listen,required"`
	Domains string   `conf:"dns.domains,required"`
	Arec    string   `conf:"dns.a"`
	AAAArec string   `conf:"dns.aaaa"`
	Ttl     uint32   `conf:"dns.ttl"`

	bhm  sync.RWMutex // for future file update
	bh   map[string]struct{}
	a    net.IP
	aaaa net.IP
	srv  []*dns.Server
}

var (
	opt = &Conf{Ttl: 3600}
)

func Init(xc *xtoml.XConf) error {
	err := xc.LoadConf(opt)
	if err != nil {
		return err
	}
	opt.bh = make(map[string]struct{})
	if err = opt.updateFile(); err != nil {
		return err
	}
	opt.a = net.ParseIP(opt.Arec).To4()
	if len(opt.a) == 0 {
		xlog.Warnf("invalid A value: %s", opt.Arec)
	}
	opt.aaaa = net.ParseIP(opt.AAAArec).To16()
	if len(opt.aaaa) == 0 {
		xlog.Warnf("invalid AAAA value: %s", opt.AAAArec)
	}
	for _, addr := range opt.Listen {
		opt.srv = append(opt.srv, &dns.Server{
			Addr:      addr,
			Net:       "udp",
			Handler:   opt,
			UDPSize:   4096,
			ReusePort: true,
			ReuseAddr: true,
		})
	}
	for _, s := range opt.srv {
		go opt.dnsMain(s)
	}
	return nil
}

func (c *Conf) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	e := xlog.GetEmptyEntry()
	defer xlog.PutEntrySilent(e)
	if len(r.Question) != 1 {
		e.Errorf("invalid question len: %d", len(r.Question))
		return
	}
	q := r.Question[0]
	e.AddField("name", dns.Name(q.Name).String())
	e.AddField("type", dns.Type(q.Qtype).String())
	e.AddField("class", dns.Class(q.Qclass).String())
	var rsp *dns.Msg
	var err error
	if c.check(q.Name) {
		e.AddField("blacklist", true)
		rsp = r.SetReply(r)
		rsp.Authoritative = true
		rsp.SetRcode(r, dns.RcodeNotImplemented)
		if q.Qclass == dns.ClassINET {
			rsp.SetRcode(r, dns.RcodeNameError)
			if q.Qtype == dns.TypeA && c.a != nil {
				rsp.SetRcode(r, dns.RcodeSuccess)
				rsp.Answer = append(rsp.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: q.Qtype,
						Class:  q.Qclass,
						Ttl:    c.Ttl,
					},
					A: c.a,
				})
			} else if q.Qtype == dns.TypeAAAA && c.aaaa != nil {
				rsp.SetRcode(r, dns.RcodeSuccess)
				rsp.Answer = append(rsp.Answer, &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: q.Qtype,
						Class:  q.Qclass,
						Ttl:    c.Ttl,
					},
					AAAA: c.aaaa,
				})
			}
		}
	} else {
		rsp, err = dnsclt.Resolve(r)
		if err != nil {
			e.Errorf("resolve: %v", err)
			return
		}
	}
	if err = w.WriteMsg(rsp); err != nil {
		e.Errorf("write: %v", err)
		return
	}
	e.Info()
}

func (c *Conf) dnsMain(s *dns.Server) {
	xlog.Fatal(s.ListenAndServe())
}

func validChar(c byte) bool {
	if c >= 'a' && c <= 'z' {
		return true
	}
	if c >= '0' && c <= '9' {
		return true
	}
	return false
}

func (c *Conf) updateFile() error {
	f, err := os.Open(c.Domains)
	if err != nil {
		return err
	}
	defer f.Close()

	c.bhm.Lock()
	defer c.bhm.Unlock()
	for k := range c.bh {
		delete(c.bh, k)
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		name := dns.CanonicalName(sc.Text())
		if !validChar(name[0]) {
			xlog.Infof("skip invalid: %s", sc.Text())
			continue
		}
		if _, ok := c.bh[name]; ok {
			xlog.Infof("skip duplicate: %s", name)
			continue
		}
		c.bh[name] = struct{}{}
	}
	if err = sc.Err(); err != nil {
		return err
	}
	xlog.Infof("loaded %d domains", len(c.bh))
	return nil
}

func (c *Conf) check(name string) bool {
	c.bhm.RLock()
	defer c.bhm.RUnlock()
	_, ok := c.bh[dns.CanonicalName(name)]
	return ok
}
