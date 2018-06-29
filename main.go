package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"
	"path"

	"github.com/google/martian"
	mapi "github.com/google/martian/api"
	"github.com/google/martian/cors"
	"github.com/google/martian/fifo"
	"github.com/google/martian/har"
	"github.com/google/martian/httpspec"
	"github.com/google/martian/marbl"
	"github.com/google/martian/martianhttp"
	"github.com/google/martian/mitm"
	"github.com/google/martian/servemux"
	"github.com/google/martian/trafficshape"
	"github.com/google/martian/verify"

	_ "github.com/google/martian/body"
	_ "github.com/google/martian/cookie"
	_ "github.com/google/martian/failure"
	_ "github.com/google/martian/martianurl"
	_ "github.com/google/martian/method"
	_ "github.com/google/martian/pingback"
	_ "github.com/google/martian/port"
	_ "github.com/google/martian/priority"
	_ "github.com/google/martian/querystring"
	_ "github.com/google/martian/skip"
	_ "github.com/google/martian/stash"
	_ "github.com/google/martian/static"
	_ "github.com/google/martian/status"

	"log"
	"bufio"
	"fmt"
)


var (
	addr           = flag.String("addr", ":8080", "host:port of the proxy")
	apiAddr        = flag.String("api-addr", ":8181", "host:port of the configuration API")
	tlsAddr        = flag.String("tls-addr", ":4443", "host:port of the proxy over TLS")
	api            = flag.String("api", "martian.proxy", "hostname for the API")
	generateCA     = flag.Bool("generate-ca-cert", false, "generate CA certificate and private key for MITM")
	cert           = flag.String("cert", "", "filepath to the CA certificate used to sign MITM certificates")
	key            = flag.String("key", "", "filepath to the private key of the CA used to sign MITM certificates")
	organization   = flag.String("organization", "Martian Proxy", "organization name for MITM certificates")
	validity       = flag.Duration("validity", time.Hour, "window of time that MITM certificates are valid")
	allowCORS      = flag.Bool("cors", false, "allow CORS requests to configure the proxy")
	harLogging     = flag.Bool("har", false, "enable HAR logging API")
	marblLogging   = flag.Bool("marbl", false, "enable MARBL logging API")
	trafficShaping = flag.Bool("traffic-shaping", false, "enable traffic shaping API")
	skipTLSVerify  = flag.Bool("skip-tls-verify", false, "skip TLS server verification; insecure")
	dsProxyURL     = flag.String("downstream-proxy-url", "", "URL of downstream proxy")
)



func main() {
	p := martian.NewProxy()
	defer p.Close()

	tr := GetRoundTripper()
	p.SetRoundTripper(tr)

	if *dsProxyURL != "" {
		u, err := url.Parse(*dsProxyURL)
		if err != nil {
			log.Fatal(err)
		}
		p.SetDownstreamProxy(u)
	}

	mux := http.NewServeMux()

	x509c, priv := ManageProxyCertificate()

	SetUpTLS(x509c, priv, p, mux)

	stack, fg := httpspec.NewStack("martian")

	topg := redirectTrafic(mux, stack)

	p.SetRequestModifier(topg)
	p.SetResponseModifier(topg)

	//New martian modifier
	m := MartianModifier(fg)

	//Log conf for har files
	SetHarLogging(mux, stack)

	//Log conf streams http logs
	SetMarblLogging(mux, stack)

	// Configure modifiers.
	configure("/configure", m, mux)

	VerifyAssertions(m, mux)

	// Reset verifications.
	ResetVerifications(m, mux)

	l, err := SetTCPAddress(mux)

	lAPI := SetTCPApiAddress(err)

	log.Printf("martian: starting proxy on %s and api on %s", l.Addr().String(), lAPI.Addr().String())

	go p.Serve(l)

	go http.Serve(lAPI, mux)

	WraperLogs(l)

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, os.Kill)

	<-sigc

	log.Println("martian: shutting down")
}

func MartianModifier(fg *fifo.Group) *martianhttp.Modifier {
	//NewModifier returns a new martianhttp.Modifier.
	//martian/martianhttp
	m := martianhttp.NewModifier()
	fg.AddRequestModifier(m)
	fg.AddResponseModifier(m)
	return m
}

//Create API Server
func SetTCPApiAddress(err error) net.Listener {
	lAPI, err := net.Listen("tcp", *apiAddr)
	if err != nil {
		log.Fatal(err)
	}
	return lAPI
}

//Create Server
func SetTCPAddress(mux *http.ServeMux) (net.Listener, error) {
	l, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	if *trafficShaping {
		tsl := trafficshape.NewListener(l)
		tsh := trafficshape.NewHandler(tsl)
		configure("/shape-traffic", tsh, mux)

		l = tsl
	}
	return l, err
}

func ResetVerifications(m *martianhttp.Modifier, mux *http.ServeMux) {
	rh := verify.NewResetHandler()
	rh.SetRequestVerifier(m)
	rh.SetResponseVerifier(m)
	configure("/verify/reset", rh, mux)
}

func VerifyAssertions(m *martianhttp.Modifier, mux *http.ServeMux) {
	// Verify assertions.
	vh := verify.NewHandler()
	vh.SetRequestVerifier(m)
	vh.SetResponseVerifier(m)
	configure("/verify", vh, mux)
}

func SetMarblLogging(mux *http.ServeMux, stack *fifo.Group) {
	if *marblLogging {
		//NewHandler instantiates a Handler with an empty set of subscriptions.
		//google/martian/marbl
		lsh := marbl.NewHandler()
		lsm := marbl.NewModifier(lsh)
		muxf := servemux.NewFilter(mux)
		muxf.RequestWhenFalse(lsm)
		muxf.ResponseWhenFalse(lsm)
		stack.AddRequestModifier(muxf)
		stack.AddResponseModifier(muxf)

		// retrieve binary marbl logs
		mux.Handle("/binlogs", LogWrapper(lsh))
	}

}

func SetHarLogging(mux *http.ServeMux, stack *fifo.Group) {

	if *harLogging {
		hl := har.NewLogger()
		muxf := servemux.NewFilter(mux)
		// Only append to HAR logs when the requests are not API requests,
		// that is, they are not matched in http.DefaultServeMux
		muxf.RequestWhenFalse(hl)
		muxf.ResponseWhenFalse(hl)

		stack.AddRequestModifier(muxf)
		stack.AddResponseModifier(muxf)

		configure("/logs", har.NewExportHandler(hl), mux)
		configure("/logs/reset", har.NewResetHandler(hl), mux)
	}
}


func redirectTrafic(mux *http.ServeMux, stack *fifo.Group) *fifo.Group {
	// wrap stack in a group so that we can forward API requests to the API port
	// before the httpspec modifiers which include the via modifier which will
	// trip loop detection
	topg := fifo.NewGroup()
	// Redirect API traffic to API server.
	if *apiAddr != "" {
		apip := strings.Replace(*apiAddr, ":", "", 1)
		port, err := strconv.Atoi(apip)
		if err != nil {
			log.Fatal(err)
		}
		// Forward traffic that pattern matches in http.DefaultServeMux
		apif := servemux.NewFilter(mux)
		apif.SetRequestModifier(mapi.NewForwarder("", port))
		topg.AddRequestModifier(apif)
	}
	topg.AddRequestModifier(stack)
	topg.AddResponseModifier(stack)
	return topg
}

//RoundTripper is an interface representing the ability to execute a single
//HTTP transaction, obtaining the Response for a given Request
//It sits in between the low level stuff like dialing, tcp, etc. and the
//high level details of HTTP (redirects, etc.)
//RoundTrip is the method do do a single round trip of request sent to server,
//server answers with response
func GetRoundTripper() *http.Transport {
	tr := &http.Transport{
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: *skipTLSVerify,
		},
	}
	return tr
}

func SetUpTLS(x509c *x509.Certificate, priv interface{}, p *martian.Proxy, mux *http.ServeMux) {
	if x509c != nil && priv != nil {
		//NewConfig creates a MITM config using the CA certificate
		//and private key to generate on-the-fly certificates.
		//google/martian/mitm
		mc, err := mitm.NewConfig(x509c, priv)
		if err != nil {
			log.Fatal(err)
		}

		mc.SetValidity(*validity)
		mc.SetOrganization(*organization)
		mc.SkipTLSVerify(*skipTLSVerify)

		//SetMITM sets the config to use for MITMing of CONNECT requests.
		//google/martian
		p.SetMITM(mc)

		// Expose certificate authority.
		ah := martianhttp.NewAuthorityHandler(x509c)
		configure("/authority.cer", ah, mux)

		// Start TLS listener for transparent MITM.
		tl, err := net.Listen("tcp", *tlsAddr)

		if err != nil {
			log.Fatal(err)
		}

		go p.Serve(tls.NewListener(tl, mc.TLS()))
	}
}

func ManageProxyCertificate() (*x509.Certificate, interface{}) {
	var x509c *x509.Certificate
	var priv interface{}
	if *generateCA {
		var err error

		//NewAuthority creates a new CA certificate and associated private key.
		//google/martian/mitm
		x509c, priv, err = mitm.NewAuthority("martian.proxy", "Martian Authority", 30*24*time.Hour)
		if err != nil {
			log.Fatal(err)
		}
	} else if *cert != "" && *key != "" {
		//LoadX509KeyPair reads and parses a public/private key pair from a pair of files.
		//The files must contain PEM encoded data. The certificate file may contain intermediate
		//certificates following the leaf certificate to form a certificate chain.
		//On successful return, Certificate.Leaf will be nil because the parsed form of the certificate is not retained.
		tlsc, err := tls.LoadX509KeyPair(*cert, *key)
		if err != nil {
			log.Fatal(err)
		}
		priv = tlsc.PrivateKey

		x509c, err = x509.ParseCertificate(tlsc.Certificate[0])
		if err != nil {
			log.Fatal(err)
		}
	}
	return x509c, priv
}

func init() {
	martian.Init()
}

// configure installs a configuration handler at path.
func configure(pattern string, handler http.Handler, mux *http.ServeMux) {
	if *allowCORS {
		handler = cors.NewHandler(handler)
	}

	// register handler for martian.proxy to be forwarded to
	// local API server
	//handler
	mux.Handle(path.Join(*api, pattern), handler)
	// register handler for local API server
	p := path.Join("localhost"+*apiAddr, pattern)
	mux.Handle(p, handler)
}


func LogWrapper(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println(r)
		h.ServeHTTP(w, r)
		log.Println("holaa")
	})
}


func WraperLogs(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Println("Error accepting connection. ", err)
		}
		go HandleConnection(conn)
	}
}


// Forward the request to the remote host and pass response back to client
func HandleConnection(localConn net.Conn) {
	brw := bufio.NewReadWriter(bufio.NewReader(localConn), bufio.NewWriter(localConn))

	var req *http.Request

	reqc := make(chan *http.Request, 1)
	errc := make(chan error, 1)
	r, err := http.ReadRequest(brw.Reader)

	if err != nil {
		errc <- err
		return
	}

	reqc <- r
	req = <-reqc

	log.Printf(formatRequest(req))

	defer req.Body.Close()
}


func formatRequest(r *http.Request) string {
	// Create return string
	var request []string
	// Add the request string
	url := fmt.Sprintf("%v %v %v", r.Method, r.URL, r.Proto)
	request = append(request, url)
	// Add the host
	request = append(request, fmt.Sprintf("Host: %v", r.Host))
	// Loop through headers
	for name, headers := range r.Header {
		name = strings.ToLower(name)
		for _, h := range headers {
			request = append(request, fmt.Sprintf("%v: %v", name, h))
		}
	}

	// If this is a POST, add post data
	if r.Method == "POST" {
		r.ParseForm()
		request = append(request, "\n")
		request = append(request, r.Form.Encode())
	}
	// Return the request as a string
	return strings.Join(request, "\n")
}

