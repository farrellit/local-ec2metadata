package main

import (
	"encoding/json"
  "errors"
	"fmt"
	"github.com/satori/go.uuid"
	"net/http"
	"strings"
)

type Node struct {
	Children map[string]*Node
	Item     interface{}
	parent   *Node
	ID       string
}

func (n *Node) GetPath  []string{
  components = make([]string,1)
  components[0] = n.ID
  if n.parent != nil {
    components = append(n.parent.GetPath(), components...)
  }
}

func NewNodeID(item interface{}, id string) *Node{
  n = NewNode(item)
  n.ID = id
}

func NewNode(item interface{}) *Node {
	n := new(Node)
	n.Children = make(map[string]*Node)
	n.Item = item
	n.ID = uuid.Must(uuid.NewV4()).String()
	if item == nil {
		n.ID = ""
	} else {
		n.ID = uuid.Must(uuid.NewV4()).String()
	}
	return n
}

func (n *Node) AddChild(c *Node) {
	c.parent = n
	n.Children[c.ID] = c
}

func (n *Node) FindChild(id string) (c *Node) {
	var ok bool
	if c, ok = n.Children[id]; !ok {
		c = nil
	}
	return c
}

func (n *Node) CrawlChildren(ids []string) *Node {
	if len(ids) == 0 {
		return n
	} else if ids[0] == n.ID { // entrypoint is a bit different
		if len(ids) == 1 {
			return n
		} else {
			ids = ids[1:len(ids)]
		}
	}
	c := n.FindChild(ids[0])
	if c == nil {
		return nil
	} else {
		return c.CrawlChildren(ids[1:len(ids)])
	}
}

func (n *Node)Jsonify() (string, error) {
  if j, e := json.MarshalIndent(n,"", " "); e != nil {
    return "", e
  } else {
    return string(j), nil
  }
}

func (n *Node)MustJsonify() string {
  j, e := n.Jsonify()
  if e != nil { panic(e) }
  return j
}

func GetPathComponents(path string) []string {
	res := make([]string, 0)
	for i, component := range strings.Split(path, "/") {
		if !(component == "" && i > 0) {
			res = append(res, component)
		}
	}
	return res
}

type NodeServer struct {
	Requests chan NodeServerRequest
	Shutdown chan bool
	root     *Node
}

func NewNodeServer(root *Node) *NodeServer {
	ns := new(NodeServer)
	ns.Requests = make(chan NodeServerRequest, 1) // buffer?
  ns.root = root
	go ns.DoNodeServer()
	return ns
}

func (ns *NodeServer) DoNodeServer() {
  for {
	  select {
	    case req := <-ns.Requests:
		    ns.ServeRequest(req)
	    case <-ns.Shutdown:
		    break
	  }
  }
	return
}


func (ns *NodeServer) ServeRequest(req NodeServerRequest) {
	req.ResponseChannel() <- req.Fulfill(ns.root)
}

type NodeServerResponse interface{}

type NodeServerRequest interface {
	ResponseChannel() chan NodeServerResponse
	Fulfill(*Node) NodeServerResponse // this iwll run in the context of the server
}

type FulfillFunc func(*Node) NodeServerResponse

/* StandardRequest comes with its own methods that can be used after, eg
sr = NewStandardRequest
sr.fulfill = sr.EnumerateRequest
*/

type StandardRequest struct {
	responseChan chan NodeServerResponse
	fulfill      FulfillFunc
  args         interface{}
}

func (sr StandardRequest) MakeRequest(ns *NodeServer) NodeServerResponse {
	ns.Requests <- sr
	return <-sr.responseChan
}

func NewStandardRequest() *StandardRequest {
	sr := new(StandardRequest)
	sr.responseChan = make(chan NodeServerResponse, 1)
	return sr
}

func (sr StandardRequest) Fulfill(root *Node) NodeServerResponse {
	return sr.fulfill(root)
}

func (sr StandardRequest) ResponseChannel() chan NodeServerResponse {
	return sr.responseChan
}

func (sr *StandardRequest) EnumerateRequest(root *Node) NodeServerResponse {
	j, err := json.MarshalIndent(root, "", " ")
	if err != nil {
		return err
	}
	return string(j)
}

func (sr *StandardRequest) FindRequest(root *Node) NodeServerResponse {
  var components []string
  if path, ok := sr.args.(string); ok {
    components = GetPathComponents(path)
  } else if path, ok := sr.args.([]string); ok {
    components = path
  } else {
    return errors.New(fmt.Sprintf("Bad argument type %T to find request; expected string or []string",sr.args))
  }
  return root.CrawlChildren(components).MustJsonify()
}

type AddRequestArgs struct {
  location []string
  data {}interface
  id string
}

func (sr *StandardRequest) AddRequest(root *Node) NodeServerResponse {
  if args , ok := sr.args.(string); !ok {
    return errors.New(fmt.Sprintf("Bad argument type %T to find request; expected string or []string",sr.args))
  }
  loc := root.CrawlChildren(components)
  if loc == nil {
    return errors.New(fmt.Sprintf("Nothing at path /%s", strings.Join(location, "/")) )
  }
  if args.id != "" {
    node = NewNodeID(data,id)
  } else {
    node = NewNode(data)
  }
  loc.AddChild(node)
  return node.GetPath()
}

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
