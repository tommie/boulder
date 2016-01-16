// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/miekg/dns"
)

type testSrv struct {
	mu         *sync.RWMutex
	txtRecords map[string]string
}

type setRequest struct {
	Host  string `json:"host"`
	Value string `json:"value"`
}

func (ts *testSrv) setTXT(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/set-txt" {
		http.NotFound(w, r)
		return
	} else if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	msg, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var sr setRequest
	err = json.Unmarshal(msg, &sr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if sr.Host == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.txtRecords[strings.ToLower(sr.Host)] = sr.Value
	fmt.Printf("dns-srv: added TXT record for %s containing \"%s\"\n", sr.Host, sr.Value)
	w.WriteHeader(http.StatusOK)
}

func (ts *testSrv) dnsHandler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	// Normally this test DNS server will return 127.0.0.1 for everything.
	// However, in some situations (for instance Docker), it's useful to return a
	// different hardcoded host. You can do so by setting the FAKE_DNS environment
	// variable.
	fakeDNS := os.Getenv("FAKE_DNS")
	if fakeDNS == "" {
		fakeDNS = "127.0.0.1"
	}
	for _, q := range r.Question {
		fmt.Printf("dns-srv: Query -- [%s] %s\n", q.Name, dns.TypeToString[q.Qtype])
		switch q.Qtype {
		case dns.TypeA:
			record := new(dns.A)
			record.Hdr = dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    0,
			}
			if fakeDNS == "hosts" {
				ips, err := lookupStaticIP(strings.TrimRight(q.Name, "."))
				if err != nil {
					m.SetRcode(r, dns.RcodeServerFailure)
					continue
				}
				record.A = ips[0]
			} else {
				record.A = net.ParseIP(fakeDNS)
			}

			m.Answer = append(m.Answer, record)
		case dns.TypeMX:
			record := new(dns.MX)
			record.Hdr = dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeMX,
				Class:  dns.ClassINET,
				Ttl:    0,
			}
			record.Mx = "mail." + q.Name
			record.Preference = 10

			m.Answer = append(m.Answer, record)
		case dns.TypeTXT:
			ts.mu.RLock()
			value, present := ts.txtRecords[q.Name]
			ts.mu.RUnlock()
			if !present {
				continue
			}
			record := new(dns.TXT)
			record.Hdr = dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    0,
			}
			record.Txt = []string{value}
			m.Answer = append(m.Answer, record)
		case dns.TypeCAA:
			if q.Name == "bad-caa-reserved.com." || q.Name == "good-caa-reserved.com." {
				record := new(dns.CAA)
				record.Hdr = dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeCAA,
					Class:  dns.ClassINET,
					Ttl:    0,
				}
				record.Tag = "issue"
				if q.Name == "bad-caa-reserved.com." {
					record.Value = "sad-hacker-ca.invalid"
				} else if q.Name == "good-caa-reserved.com." {
					record.Value = "happy-hacker-ca.invalid"
				}
				m.Answer = append(m.Answer, record)
			}
		}
	}

	auth := new(dns.SOA)
	auth.Hdr = dns.RR_Header{Name: "boulder.invalid.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 0}
	auth.Ns = "ns.boulder.invalid."
	auth.Mbox = "master.boulder.invalid."
	auth.Serial = 1
	auth.Refresh = 1
	auth.Retry = 1
	auth.Expire = 1
	auth.Minttl = 1
	m.Ns = append(m.Ns, auth)

	w.WriteMsg(m)
	return
}

func (ts *testSrv) serveTestResolver() {
	dns.HandleFunc(".", ts.dnsHandler)
	dnsServer := &dns.Server{
		Addr:         "127.0.0.1:8053",
		Net:          "tcp",
		ReadTimeout:  time.Millisecond,
		WriteTimeout: time.Millisecond,
	}
	go func() {
		err := dnsServer.ListenAndServe()
		if err != nil {
			fmt.Println(err)
			return
		}
	}()
	webServer := &http.Server{
		Addr:    "localhost:8055",
		Handler: http.HandlerFunc(ts.setTXT),
	}
	go func() {
		err := webServer.ListenAndServe()
		if err != nil {
			fmt.Println(err)
			return
		}
	}()
}

// lookupStaticIP looks up the name in /etc/hosts. It is like
// net.lookupStaticIP but does not cache entries blindly. This works
// better with Docker, which keeps updating the hosts file when
// containers are added to networks.
func lookupStaticIP(name string) ([]net.IP, error) {
	hm, err := allHosts()
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	return hm[name], nil
}

// allHosts returns all hosts in /etc/hosts. It loads the file if its
// mtime has changed since it was last loaded.
func allHosts() (map[string][]net.IP, error) {
	path := "/etc/hosts"
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if hosts == nil || hostsTime.Before(st.ModTime()) {
		hm, err := loadHosts(path)
		if err != nil {
			return nil, err
		}
		hosts = hm
		hostsTime = st.ModTime()
	}

	return hosts, nil
}

var (
	hosts        map[string][]net.IP
	hostsTime    time.Time
	hostsFieldRE = regexp.MustCompile("\\s+")
)

// loadHosts loads hosts from the given path.
func loadHosts(path string) (map[string][]net.IP, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return readHosts(f)
}

// readHosts reads and parses a hosts file.
func readHosts(r io.Reader) (map[string][]net.IP, error) {
	br := bufio.NewReader(r)
	ret := map[string][]net.IP{}
	for {
		l, err := br.ReadString('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		l = strings.TrimSpace(l)
		if l == "" || l[0] == '#' {
			continue
		}

		fs := hostsFieldRE.Split(l, -1)
		addr := net.ParseIP(fs[0])
		if addr == nil {
			continue
		}
		for _, name := range fs[1:] {
			ret[name] = append(ret[name], addr)
		}
	}
	return ret, nil
}

func main() {
	fmt.Println("dns-srv: Starting test DNS server")
	ts := testSrv{mu: new(sync.RWMutex), txtRecords: make(map[string]string)}
	ts.serveTestResolver()
	forever := make(chan bool, 1)
	<-forever
}
