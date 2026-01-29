package main

import (
	"log"
	"net/http"
	"powershellbuilder/handlers"
	"embed"
	"html/template"
)
var content embed.FS

var tpl *template.Template

func init() {
	tpl = template.Must(template.ParseFS(content, "templates/index.html"))
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if err := tpl.Execute(w, nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/build", handlers.BuildHandler)

	log.Println("[+] Server started at http://localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("[-] Failed to start server: %v", err)
	}
}