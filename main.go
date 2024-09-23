package main

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"
)

func main() {
	http.HandleFunc("/", serveHTML)
	http.HandleFunc("/chat", chatHandler)

	port := 5555
	fmt.Printf("サーバーを起動しました。http://localhost:%d にアクセスしてください。", port)
	http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}

func serveHTML(w http.ResponseWriter, r *http.Request) {
	content, err := os.ReadFile("index.html")
	if err != nil {
		http.Error(w, "ファイルの読み込みに失敗しました", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	w.Write(content)
}

func chatHandler(w http.ResponseWriter, r *http.Request) {
	dump, err := httputil.DumpRequest(r, true)
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	// ダンプをコンソールに出力
	fmt.Printf("%s\n", dump)

	var websocketKey = r.Header.Get("Sec-WebSocket-Key")
	if websocketKey == "" {
		http.Error(w, "websocket key not found", http.StatusBadRequest)
		return
	}

	const WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	sha1 := sha1.New()
	sha1.Write([]byte(websocketKey + WEBSOCKET_GUID))
	var websocketAccept = base64.StdEncoding.EncodeToString(sha1.Sum(nil))
	fmt.Printf("websocketAccept: %s\n", websocketAccept)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "WebSocket not supported", http.StatusInternalServerError)
		return
	}
	conn, bufrw, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	// ハンドシェイクレスポンスの送信
	bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	bufrw.WriteString("Upgrade: websocket\r\n")
	bufrw.WriteString("Connection: Upgrade\r\n")
	bufrw.WriteString("Sec-WebSocket-Accept: " + websocketAccept + "\r\n")
	bufrw.WriteString("\r\n")
	bufrw.Flush()
}
