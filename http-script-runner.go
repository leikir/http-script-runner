package main

import (
  "crypto/tls"
  "fmt"
  "flag"
  "log"
  "net/http"
  "strconv"
)

func handler(w http.ResponseWriter, req *http.Request) {
  w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")

  fmt.Fprintf(w, "Hello %s!\n", req.URL.Path[1:])
}

func main() {
  portPtr := flag.Int("port", 443, "an int")
  certPathPtr := flag.String("cert", "fullchain.pem", "a string")
  keyPathPtr := flag.String("key", "privkey.pem", "a string")
  flag.Parse()
  port := *portPtr
  certPath := *certPathPtr
  keyPath := *keyPathPtr

  fmt.Println("port:", port)
  fmt.Println("certPath:", certPath)
  fmt.Println("keyPath:", keyPath)

  mux := http.NewServeMux()
  mux.HandleFunc("/", handler);
  cfg := &tls.Config{
    MinVersion:               tls.VersionTLS12,
    CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
    PreferServerCipherSuites: true,
    CipherSuites: []uint16{
      tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
      tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
      tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
      tls.TLS_RSA_WITH_AES_256_CBC_SHA,
    },
  }

  srv := &http.Server{
    Addr:         ":" + strconv.Itoa(port),
    Handler:      mux,
    TLSConfig:    cfg,
    TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
  }
  log.Fatal(srv.ListenAndServeTLS(certPath, keyPath))
}
