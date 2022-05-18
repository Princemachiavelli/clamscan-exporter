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

var filesMetrics = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "clamscan_files",
	Help: "The number of scanned files",
}, []string{"code", "virus", "path"})

var durationMetrics = promauto.NewSummary(prometheus.SummaryOpts{
	Name: "clamscan_duration_seconds",
	Help: "duration of clamscan"})

func main() {
	var tcpPort, httpPort string
	flag.StringVar(&tcpPort, "tcp-port", "9000", "port to listen to tcp connections on from clamscan netcat pipe")
	flag.StringVar(&httpPort, "http-port", "9967", "port to listen to http connections from prometheus for /metrics")
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

	startTime := time.Now()

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

		if isErrorLine(scanner.Text()) {
			// only log errors since it can be of high cardinality if many files are scanned.
			logrus.Error(scanner.Text())
			continue
		}

		if _, ok := result[code]; !ok {
			if len(code) > 20 {
				logrus.Warnf("found very long code. This is the whole line: %s", scanner.Text())
			}
			result[code] = 1
			continue
		}
		result[code]++
	}

	durationMetrics.Observe(time.Since(startTime).Seconds())

	if scanner.Err() != nil {
		logrus.Error(scanner.Err())
	}
	for code, count := range result {
		filesMetrics.WithLabelValues(code, "", "").Set(float64(count))
	}
	for virus, path := range found {
		filesMetrics.WithLabelValues("FOUND", virus, path).Set(1)
	}
}

func isErrorLine(line string) bool {
	// Add more errors here if needed. Found some of them here: https://github.com/Cisco-Talos/clamav/blob/main/clamscan/manager.c
	if strings.HasPrefix(line, "Can't open file") {
		return true
	}
	if strings.HasSuffix(line, "Can't open directory.") {
		return true
	}
	if strings.HasSuffix(line, " Can't access file") {
		return true
	}
	if strings.HasSuffix(line, " Not supported file type") {
		return true
	}
	if strings.HasSuffix(line, " ERROR") {
		return true
	}
	return false
}
