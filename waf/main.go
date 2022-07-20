package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/corazawaf/coraza/v2"
	"github.com/corazawaf/coraza/v2/seclang"
)

var waf *coraza.Waf

// NewProxy takes target host and creates a reverse proxy
func NewProxy(targetHost string) (*httputil.ReverseProxy, error) {
	url, err := url.Parse(targetHost)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(url)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
	}
	proxy.ErrorHandler = errorHandler()
	return proxy, nil
}

// ProxyRequestHandler handles the http request using proxy
func ProxyRequestHandler(proxy *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		tx := waf.NewTransaction()
		defer tx.ProcessLogging()
		if it, _ := tx.ProcessRequest(r); it != nil {
			fmt.Printf("Transaction was interrupted with status %d\n", it.Status)
			fmt.Printf("Rule blocked: %d\n", it.RuleID)
			w.Write([]byte("WAF BLOCKED!"))
		} else {
			proxy.ServeHTTP(w, r)
		}
	}
}

func errorHandler() func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, req *http.Request, err error) {
		fmt.Printf("Got error while modifying response: %v \n", err)
		return
	}
}

func main() {

	// First we initialize our waf and our seclang parser
	waf = coraza.NewWaf()
	parser, _ := seclang.NewParser(waf)
	files := []string{
		"coraza.conf",
		"coreruleset/crs-setup.conf.example",
		"coreruleset/rules/*.conf",
	}
	for _, f := range files {
		if err := parser.FromFile(f); err != nil {
			panic(err)
		}
	}

	// initialize a reverse proxy and pass the actual backend server url here
	proxy, err := NewProxy("http://backend")
	if err != nil {
		panic(err)
	}

	// handle all requests to your server using the proxy
	http.HandleFunc("/", ProxyRequestHandler(proxy))
	log.Fatal(http.ListenAndServe(":80", nil))
}
