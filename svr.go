package main

import (
  "github.com/farrellit/local-ec2metadata/authcontext"
  "fmt"
  "strings"
  "net/http"
  "encoding/json"
  "io/ioutil"
)

func WebResponse(ar authcontext.AuthResult, w http.ResponseWriter, render func(authcontext.AuthResult) (interface{}, uint)) {
  fmt.Println("MakeRequest complete:", ar)
  w.Header().Set("Context-Type", "application/json")
  resp , code := render(ar)
  if j, err := json.Marshal(resp); err != nil {
    w.WriteHeader(http.StatusInternalServerError)
    // only compile time error here
    errj, _ := json.Marshal(map[string]string{"Error":fmt.Sprintf("Response (type %T) could not be encoded as json",resp)})
    fmt.Fprintln(w, string(errj))
  } else {
    w.WriteHeader(code)
    fmt.Fprintln(w, string(j))
  }
}

func Options(w http.ResponseWriter, r *http.Request) bool {
  w.Header().Set("Access-Control-Allow-Origin", "*" ) // todo: howto match file:// or move on from there
  if r.Method == http.MethodOptions {
    w.WriteHeader(http.StatusOK) // todo: howto match file:// or move on from there
    return true
  }
  return false
}

// Context Put Request. I'm not sure if we'd do a Put vs Patch for renew, or whether it matters, but we would want to dedup ( ID should do it )
type ContextPutData struct {
  Token string
  Profile string
  Role string
}

func NilRender(authcontext.AuthResult)(interface{}, uint){
  return nil, 0
}

func ContextPutRequest (w http.ResponseWriter, r *http.Request) (
    request *authcontext.AuthRequest, // return nil if we need to short circuite due to error
    render func(authcontext.AuthResult)(interface{},uint),
) {
  request = nil
  render = NilRender
  body, err := ioutil.ReadAll(r.Body)
  if err != nil {
    code (http.StatusInternalServerError)
    fmt.Fprintln(w, fmt.Sprintf("Failed to read request body: %s", err.Error()))
    return
  }
  bdata, err := json.Unmarshal(body)
  if err != nil {
    w.WriteHeader(http.StatusUnsupportedMediaType)
    fmt.Fprintln(w, err.Error())
    return
  }
  if bdict, ok := bdata.(map[string]interface{}); !ok {
    w.WriteHeader(http.StatusUnprocessableEntity)
    fmt.Fprintln(w, fmt.Sprintf("Json data should have been a dict at top level.  I got %T", bdata)
    return
  }
  var token, profile string
  if token, ok := bdict['Token']; !ok {
    w.WriteHeader(http.StatusUnprocessableEntity)
    fmt.Fprintln(w, fmt.Sprintf("Json data should look like '{\"token\":\"<mfa-token>\"}."))
    return
  }
  if profile, 
        request = authcontext.NewAuthRequest(
          path,"ADD",
          authcontext.NewProfileAuthContext(path),
        )
        render = func(ar authcontext.AuthResult) (interface{}, uint) {
          return map[string]interface{}{ "Path": ar.Response}, http.StatusCreated
        }
}


func main() {
  server := authcontext.NewAuthServer()
  http.HandleFunc("/contexts", func(w http.ResponseWriter, r *http.Request){
    if Options(w, r) {
      return
    }
    var request *authcontext.AuthRequest
    var render func(authcontext.AuthResult) (interface{}, uint)
    path := strings.FieldsFunc(strings.TrimPrefix("/contexts/",r.URL.Path), func(c rune) bool { return c == '/'} )
    fmt.Println("Path: ", path)
    switch r.Method {
      case http.MethodGet:
        request = authcontext.NewAuthRequest(path,"LIST",nil)
        render = func(ar authcontext.AuthResult) (interface{}, uint) {
          return map[string]interface{}{"contexts": ar.Response}, http.StatusOk
        }
      case http.MethodPut:
    }
    if request == nil {
      w.WriteHeader(http.StatusNotFound)
    } else {
      WebResponse(server.MakeRequest(request), w, render)
    }
    return
  })
  // TODO: should be able to scan for and update profiles
  panic(http.ListenAndServe(":8001",nil))
  return
}
