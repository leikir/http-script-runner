package main

import (
  "bytes"
  "context"
  "crypto/tls"
  "fmt"
  "flag"
  "log"
  "net/http"
  "os"
  "os/exec"
  "strconv"
  "time"
)

type key int

const (
  requestIDKey key = 0
)

var (
  port int
  path string
  certPath string
  keyPath string
  scriptPath string
  basicAuthUser string
  basicAuthPass string
)

func authenticateRequest(w http.ResponseWriter, r *http.Request) bool {
  w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)

  username, password, authOK := r.BasicAuth()

  if authOK == false {
    http.Error(w, "Not authorized", 401)
    return false
  }

  if username != basicAuthUser || password != basicAuthPass {
    http.Error(w, "Not authorized", 401)
    return false
  }

  return true
}

func handler(w http.ResponseWriter, r *http.Request) {
  // prepare answer
  w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")

  // authenticate request
  if !authenticateRequest(w, r) {
    return
  }

  // only respond to /
  if r.URL.Path != path {
    http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
    return
  }

  // run script and answer
  w.Header().Set("Content-Type", "text/plain; charset=utf-8")
  w.Header().Set("X-Content-Type-Options", "nosniff")
  cmd := exec.Command(scriptPath)
  var out bytes.Buffer
  var stderr bytes.Buffer
  cmd.Stdout = &out
  cmd.Stderr = &stderr
  err := cmd.Run()
  if err != nil {
    http.Error(w, fmt.Sprint(err) + ": " + stderr.String(), http.StatusInternalServerError)
    return
  }
  w.WriteHeader(http.StatusOK)
  w.Write(out.Bytes())
}

func main() {
  flag.IntVar(&port, "port", 443, "port to listen to")
  flag.StringVar(&path, "path", "/", "unique path to listen to")
  flag.StringVar(&certPath, "cert", "fullchain.pem", "path to the SSL certificate")
  flag.StringVar(&keyPath, "key", "privkey.pem", "path to the SSL private key")
  flag.StringVar(&scriptPath, "script", "run.sh", "path to the script to be executed")
  flag.StringVar(&basicAuthUser, "user", "username", "basic auth username")
  flag.StringVar(&basicAuthPass, "pass", "password", "basic auth password")
  flag.Parse()

  fmt.Println("HTTP script runner is starting...")
  fmt.Println("* listening on:", port)
  fmt.Println("* listening at:", path)
  fmt.Println("* path to SSL certificate:", certPath)
  fmt.Println("* path to SSL private key:", keyPath)
  fmt.Println("* path to script:", scriptPath)
  fmt.Println("* basic auth username:", basicAuthUser)
  fmt.Println("* basic auth password:", basicAuthPass)

  nextRequestID := func() string {
    return fmt.Sprintf("%d", time.Now().UnixNano())
  }

  logger := log.New(os.Stdout, "http: ", log.LstdFlags)

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
    Handler:      tracing(nextRequestID)(logging(logger)(mux)),
    ErrorLog:     logger,
    TLSConfig:    cfg,
    TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
  }
  log.Fatal(srv.ListenAndServeTLS(certPath, keyPath))
}

func logging(logger *log.Logger) func(http.Handler) http.Handler {
  return func(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
      requestID, ok := r.Context().Value(requestIDKey).(string)
      if !ok {
        requestID = "unknown"
      }
      logger.Println(requestID, r.Method, r.URL.Path, r.RemoteAddr, r.UserAgent())
      next.ServeHTTP(NewLoggedResponseWriter(w, logger, requestID), r)
    })
  }
}

func tracing(nextRequestID func() string) func(http.Handler) http.Handler {
  return func(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
      requestID := r.Header.Get("X-Request-Id")
      if requestID == "" {
        requestID = nextRequestID()
      }
      ctx := context.WithValue(r.Context(), requestIDKey, requestID)
      w.Header().Set("X-Request-Id", requestID)
      next.ServeHTTP(w, r.WithContext(ctx))
    })
  }
}

// ---

type LoggedResponseWriter struct {
  http.ResponseWriter
  logger      *log.Logger
  requestID   string
  status      int
  wroteHeader bool
}

func NewLoggedResponseWriter(w http.ResponseWriter, logger *log.Logger, requestID string) *LoggedResponseWriter {
  return &LoggedResponseWriter{ResponseWriter: w, logger: logger, requestID: requestID}
}

func (w *LoggedResponseWriter) Status() int {
  return w.status
}

func (w *LoggedResponseWriter) Write(p []byte) (n int, err error) {
  if !w.wroteHeader {
    w.WriteHeader(http.StatusOK)
  }
  if w.status != http.StatusOK {
    w.logger.Println(w.requestID, "Error:", string(p))
  }
  return w.ResponseWriter.Write(p)
}

func (w *LoggedResponseWriter) WriteHeader(code int) {
  w.ResponseWriter.WriteHeader(code)
  // Check after in case there's error handling in the wrapped ResponseWriter.
  if w.wroteHeader {
    return
  }
  w.status = code
  w.wroteHeader = true
  w.logger.Println(w.requestID, "Status:", code)
}
