package forest

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/satori/go.uuid"
	"strings"
)

type Node struct {
	Children map[string]*Node
	Item     interface{}
	parent   *Node
	ID       string
}

func (n *Node) GetPath() (components []string) {
	components = make([]string, 1)
	components[0] = n.ID
	if n.parent != nil {
		components = append(n.parent.GetPath(), components...)
	}
	return
}

func NewNodeID(item interface{}, id string) *Node {
	n := NewNode(item)
	n.ID = id
	return n
}

func NewNode(item interface{}) *Node {
	n := new(Node)
	n.Children = make(map[string]*Node)
	n.Item = item
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

func (n *Node) Jsonify() (string, error) {
	if j, e := json.MarshalIndent(n, "", " "); e != nil {
		return "", e
	} else {
		return string(j), nil
	}
}

func (n *Node) MustJsonify() string {
	j, e := n.Jsonify()
	if e != nil {
		panic(e)
	}
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
	Fulfill(*Node) NodeServerResponse // this will run in the context of the server
}

type FulfillFunc func(*Node) NodeServerResponse

/* StandardRequest comes with its own methods that can be used after, eg
sr = NewStandardRequest
sr.fulfillment = sr.EnumerateRequest
*/

type StandardRequest struct {
	responseChan chan NodeServerResponse
	Fulfillment  FulfillFunc
	Args         interface{}
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
	return sr.Fulfillment(root)
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
	if path, ok := sr.Args.(string); ok {
		components = GetPathComponents(path)
	} else if path, ok := sr.Args.([]string); ok {
		components = path
	} else {
		return errors.New(fmt.Sprintf("Bad argument type %T to find request; expected string or []string", sr.Args))
	}
	return root.CrawlChildren(components).MustJsonify()
}

type AddRequestArgs struct {
	Location []string
	Data     interface{}
	Id       string
}

func (sr *StandardRequest) AddRequest(root *Node) NodeServerResponse {
	var args AddRequestArgs
	var ok bool
	if args, ok = sr.Args.(AddRequestArgs); !ok {
		return errors.New(fmt.Sprintf("Bad argument type %T to find request; expected AddRequestArgs", sr.Args))
	}
	loc := root.CrawlChildren(args.Location)
	if loc == nil {
		return errors.New(fmt.Sprintf("Nothing at path /%s", strings.Join(args.Location, "/")))
	}
	var node *Node
	if args.Id != "" {
		node = NewNodeID(args.Data, args.Id)
	} else {
		node = NewNode(args.Data)
	}
	loc.AddChild(node)
	return node.GetPath()
}
