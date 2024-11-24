package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/andrewz1/xlog"
	"github.com/andrewz1/xtoml"
)

var (
	conf = confName()
	sig  = []os.Signal{
		syscall.SIGTERM,
		syscall.SIGQUIT,
		syscall.SIGINT,
	}
)

func sigSetup() (c chan os.Signal) {
	c = make(chan os.Signal, 1)
	signal.Notify(c, sig...)
	return c
}

func sigWait(c chan os.Signal) (s os.Signal) {
	for s = range c {
		for _, ss := range sig {
			if s == ss {
				return
			}
		}
	}
	return syscall.SIGQUIT
}

func main() {
	sc := sigSetup()
	switch {
	case len(os.Args) < 2:
	case len(os.Args) == 2:
		conf = os.Args[1]
	case len(os.Args) > 2:
		xlog.Fatalf("Usage: %s [%s]\n", os.Args[0], conf)
	}
	xc, err := xtoml.LoadFile(conf)
	if err != nil {
		xlog.Fatal(err)
	}
	if err = xlog.Init(xc); err != nil {
		xlog.Fatal(err)
	}
	// main logic start
	// main logic end
	xlog.Info(sigWait(sc))
}
