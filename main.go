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
	fmt.Printf("サーバーを起動しました。http://localhost:%d にアクセスしてください。\n\n", port)
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

var dummyDB = []string{}

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
	fmt.Printf("websocketAccept: %s\n\n", websocketAccept)

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

	/*
		RFC6455 5.2. Base Framing Protocol
		  0                   1                   2                   3
			0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			+-+-+-+-+-------+-+-------------+-------------------------------+
			|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
			|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
			|N|V|V|V|       |S|             |   (if payload len==126/127)   |
			| |1|2|3|       |K|             |                               |
			+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
			|     Extended payload length continued, if payload len == 127  |
			+ - - - - - - - - - - - - - - - +-------------------------------+
			|                               |Masking-key, if MASK set to 1  |
			+-------------------------------+-------------------------------+
			| Masking-key (continued)       |          Payload Data         |
			+-------------------------------- - - - - - - - - - - - - - - - +
			:                     Payload Data continued ...                :
			+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
			|                     Payload Data continued ...                |
			+---------------------------------------------------------------+
	*/

	var firstByte = make([]byte, 1)
	_, err = conn.Read(firstByte)
	if err != nil {
		fmt.Println("Read error")
		fmt.Println(err)
		return
	}

	// FIN (1bit): 終了フレームかどうか
	var fin = firstByte[0] >> 7
	// OPCODE (4bits): %x0 … 継続フレーム, %x1 … テキストフレーム, %x2 … バイナリフレーム
	//		%x3-7 … それ以外の非制御フレームで予約されている
	//		%x8 … 接続のクローズ, %x9 … ping, %xA … pong
	// 	  %xB-F … 以降の制御フレーム用に予約されている
	var opcode = firstByte[0] & 0x0F
	fmt.Printf("1st byte: %#08b fin: %d, opcode %d\n", firstByte[0], fin, opcode)

	var secondByte = make([]byte, 1)
	_, err = conn.Read(secondByte)
	if err != nil {
		fmt.Println("Read error")
		fmt.Println(err)
		return
	}

	// MASK (1bit): ペイロードがマスクされているかどうか
	var mask = secondByte[0] >> 7
	// Payload length (7bits): ペイロードの長さ
	var payloadLength = secondByte[0] & 0x7F
	fmt.Printf("2nd byte: %#08b mask: %d, payloadLength: %d\n", secondByte[0], mask, payloadLength)

	// Masking-key: 4 bytes
	var maskKey = make([]byte, 4)
	_, err = conn.Read(maskKey)
	if err != nil {
		fmt.Println("Read error")
		fmt.Println(err)
		return
	}
	fmt.Printf("Masking-key: %#08b %#08b %#08b %#08b\n", maskKey[0], maskKey[1], maskKey[2], maskKey[3])

	// Payload data
	fmt.Printf("Payload data: ")
	var payloadBytes = make([]byte, payloadLength)
	for i := 0; i < int(payloadLength); i++ {
		data := make([]byte, 1)
		_, err = conn.Read(data)
		if err != nil {
			fmt.Println("Read error")
			fmt.Println(err)
		}
		payloadBytes[i] = data[0] ^ maskKey[i%4]
	}
	fmt.Printf("%s\n", payloadBytes)
	dummyDB = append(dummyDB, string(payloadBytes))
	fmt.Printf("dummyDB: %v\n", dummyDB)
}
