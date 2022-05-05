package main

import (
	"bufio"
	"errors"
	"flag"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jonaz/gograce"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

var scanStatusRegexp = regexp.MustCompile(`: (.*)$`)

var metrics = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "clamscan_files",
	Help: "The number of scanned files",
}, []string{"code", "virus", "path"})

func main() {
	var tcpPort, httpPort string
	flag.StringVar(&tcpPort, "tcp-port", "9000", "port to listen tcp connections on")
	flag.StringVar(&httpPort, "http-port", "8080", "port to listen tcp connections on")
	flag.Parse()
	ln, err := net.Listen("tcp", ":"+tcpPort)
	if err != nil {
		logrus.Errorf("cannot start socket listener on port %s: %s", tcpPort, err)
		return
	}
	srv, shutdown := gograce.NewServerWithTimeout(10 * time.Second)
	srv.Handler = http.DefaultServeMux
	srv.Addr = ":" + httpPort
	go func() {
		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logrus.Error(err)
		}
	}()
	http.Handle("/metrics", promhttp.Handler())
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				logrus.Error(err)
				return
			}
			wg.Add(1)
			go handleConnection(&wg, conn)
		}
	}()

	<-shutdown
	logrus.Info("shutdown initiated")
	ln.Close()
	wg.Wait()
}

func handleConnection(wg *sync.WaitGroup, c net.Conn) {
	logrus.Debugf("Serving %s", c.RemoteAddr().String())
	defer wg.Done()
	defer c.Close()

	result := make(map[string]int)
	found := make(map[string]string)

	scanner := bufio.NewScanner(c)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		match := scanStatusRegexp.FindSubmatch(scanner.Bytes())
		if len(match) < 2 {
			continue
		}
		code := string(match[1])

		if strings.HasSuffix(code, "FOUND") {
			path := strings.TrimSuffix(strings.Replace(scanner.Text(), code, "", 1), ": ")
			found[code[0:len(code)-6]] = path
			continue
		}
		if _, ok := result[code]; !ok {
			result[code] = 1
			continue
		}
		result[code]++
	}

	if scanner.Err() != nil {
		logrus.Error(scanner.Err())
	}
	for code, count := range result {
		metrics.WithLabelValues(code, "", "").Set(float64(count))
	}
	for virus, path := range found {
		metrics.WithLabelValues("FOUND", virus, path).Set(1)
	}
}
