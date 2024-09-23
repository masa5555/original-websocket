package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/", serveHTML)
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
