package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/farrellit/local-ec2metadata/forest"
	"net/http"
	"strings"
)

func main() {
	root := forest.NewNode(nil)
	for i := 0; i < 10; i++ {
		j := new(int)
		*j = i
		n := forest.NewNode(j)
		for j := 0; j < i; j++ {
			j2 := new(int)
			*j2 = j
			n.AddChild(forest.NewNode(j2))
		}
		root.AddChild(n)
	}
	ns := forest.NewNodeServer(root)
	http.HandleFunc("/nodes/", func(w http.ResponseWriter, r *http.Request) {
		req := forest.NewStandardRequest()
		if r.Method == http.MethodPost { // Adding Nodes
			req.Fulfillment = req.AddRequest
			req.Args = forest.AddRequestArgs{
        Location: strings.Split(strings.TrimPrefix(r.URL.Path, "/nodes"), "/"), 
        Data: new(interface{})
      }
			buf := new(bytes.Buffer)
			buf.ReadFrom(r.Body)
			if err := json.Unmarshal(buf.Bytes(), &req.Args.Data); err != nil {
				w.WriteHeader(http.StatusUnsupportedMediaType)
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprintln(w, err.Error())
				return
			}
		} else if r.Method == http.MethodGet { // Listing Nodes
			req.Fulfillment = req.FindRequest
			req.Args = strings.TrimPrefix(r.URL.Path, "/nodes")
		}
		resp := req.MakeRequest(ns)
		if err, ok := resp.(error); ok {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, err.Error())
			return
		} else if str, ok := resp.(string); ok {
			w.Header().Set("Content-Type", "application/json")
			if str == "null" {
				w.WriteHeader(http.StatusNotFound)
			}
			fmt.Fprintln(w, str)
		} else {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "Unexpected enumeration response type %T", resp)
		}
	})
	http.HandleFunc("/nodes", func(w http.ResponseWriter, r *http.Request) {
		enum_req := forest.NewStandardRequest()
		enum_req.Fulfillment = enum_req.EnumerateRequest
		resp := enum_req.MakeRequest(ns)
		if err, ok := resp.(error); ok {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "Couldn't enumerate nodes:", err.Error())
			return
		} else if str, ok := resp.(string); ok {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, str)
		} else {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "Unexpected enumeration response type %T", resp)
		}
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	panic(http.ListenAndServe(":8001", nil))
}
