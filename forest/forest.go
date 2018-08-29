package forest

import (
	"encoding/json"
  "errors"
	"fmt"
	"github.com/satori/go.uuid"
	"net/http"
	"strings"
)

func main() {
	root := NewNode(nil)
	for i := 0; i < 10; i++ {
		j := new(int)
		*j = i
		n := NewNode(j)
		for j := 0; j < i; j++ {
			j2 := new(int)
			*j2 = j
			n.AddChild(NewNode(j2))
		}
		root.AddChild(n)
	}
	ns := NewNodeServer(root)
	http.HandleFunc("/nodes/", func(w http.ResponseWriter, r *http.Request) {
		req := NewStandardRequest()
    if r.Method == http.MethodPost {
      feq.fulfill = req.FindRequest
      req.args = AddRequestArgs{location:strings.TrimPrefix(r.URL.Path,"/nodes")}
      if err := json.Unmarshal(&req.data); err != nil {
        w.Header().Set("Content-Type", "text/plain")
        w.WriteHeader(http.StatusUnsupportedMediaType)

      }
    }
    else if r.Method == http.MethodGet {
		  req.fulfill = req.FindRequest
      req.args = strings.TrimPrefix(r.URL.Path, "/nodes")
    }
		resp := req.MakeRequest(ns)
		if err, ok := resp.(error); ok {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "Couldn't find node at %s: %s", req.args.(string), err.Error())
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
		enum_req := NewStandardRequest()
		enum_req.fulfill = enum_req.EnumerateRequest
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
