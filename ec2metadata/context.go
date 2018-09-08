package main

import (
  "time"
  "errors"
  "fmt"
  "strings"
  "github.com/aws/aws-sdk-go/aws"
  "github.com/aws/aws-sdk-go/aws/session"
  "github.com/aws/aws-sdk-go/service/sts"
  "github.com/aws/aws-sdk-go/service/iam"
  "os"
  //"regexp"
)

type CredentialMaterials struct {
  KeyId string
  Secret string
  Token string
  Expiration time.Time
}

func (cm CredentialMaterials)IsExpiringWithin(td time.Duration) bool {
  return time.Now().Add(td).After(cm.Expiration)
}

type AuthContext interface {
  GetCredentials() (CredentialMaterials, error)
  Renew(string) error
  GetSubContexts() []AuthContext
  ID() string
  SetParentContext(AuthContext)
  AddSubContext(AuthContext)
  GetParentContext() AuthContext
}

type BaseAuthContext struct {
  CredentialMaterials
  Session *session.Session
  Config *aws.Config
  RenewalWindow time.Duration
  Id string
  SubContexts []AuthContext
  ParentContext AuthContext
}

func (bac *BaseAuthContext)SetParentContext(parent AuthContext) {
  bac.ParentContext = parent
}

func (bac *BaseAuthContext)GetParentContext() AuthContext {
  return bac.ParentContext
}

func (bac *BaseAuthContext)GetCredentials() (CredentialMaterials, error) {
  return bac.CredentialMaterials, nil
}

func (bac *BaseAuthContext)GetSubContexts() []AuthContext {
  return bac.SubContexts
}

func (bac *BaseAuthContext)AddSubContext(ac AuthContext) {
  bac.SubContexts = append(bac.SubContexts,ac)
}

func (bac *BaseAuthContext)ID() string {
  return bac.Id
}

func AuthContextTreeRepr(cxts []AuthContext) interface{} {
  result := make(map[string]interface{}, len(cxts))
  for _, subel := range cxts {
    result[subel.ID()] = AuthContextTreeRepr(subel.GetSubContexts())
  }
  return result
}

// A role by definition always has a prior auth 
// that isn't a role to base it on.
type RoleAuthContext struct {
}

type ProfileAuthContext struct {
  BaseAuthContext
  Profile string
  mfa_serial string
}

// this could forseeably be used by a consumer 
// to refresh serial if it changed
func (pac *ProfileAuthContext)RefreshSerial() error {
  iamc := iam.New(pac.BaseAuthContext.Session, pac.BaseAuthContext.Config)
  return iamc.ListMFADevicesPages( &iam.ListMFADevicesInput{ }, func(out *iam.ListMFADevicesOutput, more bool) bool {
    if len(out.MFADevices) > 0 {
      pac.mfa_serial = aws.StringValue(out.MFADevices[0].SerialNumber)
      return false
    }
    return more
  })
}

// .. but the consumer will not need the serial itself 
func (pac *ProfileAuthContext)getSerial() (string, error) {
  if pac.mfa_serial != "" {
    return pac.mfa_serial, nil
  }
  err := pac.RefreshSerial()
  return pac.mfa_serial, err
}

// A profile, by definition, is its own entry point for creds, or will 
// inherently include one based on another profile .  
func (pac *ProfileAuthContext) Renew(mfa string) error {
  // we know we're a profile, probably a user
  session_token_input := &sts.GetSessionTokenInput{DurationSeconds:aws.Int64(129600)}
  if mfa != "" {
    if serial, err := pac.getSerial(); err != nil {
      return err
    } else {
      session_token_input.SerialNumber=aws.String(serial)
    }
    session_token_input.TokenCode = aws.String(mfa)
  }
  stsc := sts.New(pac.BaseAuthContext.Session, pac.BaseAuthContext.Config)
  if resp, err := stsc.GetSessionToken(session_token_input); err != nil {
    return err
  } else {
    pac.CredentialMaterials = CredentialMaterials{
      KeyId: aws.StringValue(resp.Credentials.AccessKeyId),
      Secret: aws.StringValue(resp.Credentials.SecretAccessKey),
      Token: aws.StringValue(resp.Credentials.SessionToken),
      Expiration: aws.TimeValue(resp.Credentials.Expiration),
    }
    return nil
  }
}

func NewProfileAuthContext(profile string) *ProfileAuthContext {
  pac := new(ProfileAuthContext)
  pac.Profile = profile
  pac.BaseAuthContext.Session = session.Must(session.NewSessionWithOptions(session.Options{
    SharedConfigState: session.SharedConfigEnable,
    Profile: profile,
  }))
  pac.BaseAuthContext.SubContexts = make([]AuthContext,0)
  pac.BaseAuthContext.Id = fmt.Sprintf("profile/%s", profile)
  return pac
}

// AuthServer makes it possible to manipulate the auth structure from 
// many request threads by having a single threaded server behind channels

type AuthRequest struct {
  Path []string
  Operation string // CRUD
  Data interface{}
  Result chan AuthResult
}

func NewAuthRequest(path []string, op string, data interface{}) *AuthRequest {
  areq := new(AuthRequest)
  areq.Path = path
  areq.Operation = op
  areq.Data =data
  areq.Result = make(chan AuthResult,1)
  return areq
}

type AuthResult struct {
  Response interface{}
  Error error
}

type AuthServer struct {
  Requests chan *AuthRequest
  baseAuths []AuthContext
}

func ( as *AuthServer)MakeRequest(req *AuthRequest) AuthResult {
  as.Requests <- req
  defer func(){fmt.Println("MakeRequest returned")}()
  return <- req.Result
}

func (as *AuthServer) HandleRequest(req *AuthRequest) AuthResult {
  switch strings.ToUpper(req.Operation) {
    case "NOOP":
      return AuthResult{ Response: true, Error: nil }
    case "LIST":
      return as.ListRequest(req)
    case "ADD":
      return as.AddRequest(req)
  }
  return AuthResult{ Response:nil, Error:errors.New(fmt.Sprintf("Unknown Operation %s",req.Operation)) }
}

func (as *AuthServer)AddRequest(req *AuthRequest) AuthResult {
  if newel, ok := req.Data.(AuthContext); !ok {
    return AuthResult{Response:nil,Error: errors.New(fmt.Sprintf("ADD Request takes an auth context as Data, not %T", req.Data))}
  } else {
    if len(req.Path) == 0 {
      // top level is not an AuthContext, just a []AuthContext.  This is a simple case.
      newel.SetParentContext(nil)
      as.baseAuths = append(as.baseAuths, newel)
    } else if parent, err := crawlAuths(req.Path,as.baseAuths); err != nil {
      return AuthResult{Response:nil, Error: err}
    } else {
      newel.SetParentContext(parent)
      parent.AddSubContext(newel)
    }
    return AuthResult{Response: append(req.Path,newel.ID()), Error: nil }
  }
}

func (as *AuthServer)ListRequest(req *AuthRequest) AuthResult {
  var start []AuthContext
  if len(req.Path) > 0 {
    el,err := crawlAuths(req.Path,as.baseAuths)
    if err != nil {
      return AuthResult{Response:nil,Error: err}
    }
    start = el.GetSubContexts()
  } else {
    start = as.baseAuths
  }
  return AuthResult{ Response: AuthContextTreeRepr(start), Error: nil }
}

func crawlAuths(path []string, auths []AuthContext) (AuthContext, error) {
  if len(path) == 0 {
    return nil, errors.New("No path elements provided")
  }
  ids := make([]string,len(auths))
  for _, el := range auths {
    if el.ID() == path[0] {
      if len(path) == 1 {
        // the last el
        return el, nil
      } else {
        // recurse
        return crawlAuths(path[1:len(path)], el.GetSubContexts())
      }
    } else {
      ids = append(ids, el.ID())
    }
  }
  return nil, errors.New(fmt.Sprintf("Path element %s not found in %s", path[0], strings.Join(ids,", ")))
}

func (as *AuthServer)DoAuthServer() {
  for {
    select {
      case req := <-as.Requests:
        fmt.Printf("Got request op %s\n", req.Operation)
        req.Result <- as.HandleRequest(req)
    }
  }
}

func NewAuthServer() *AuthServer{
  as := new(AuthServer)
  as.Requests = make(chan *AuthRequest, 10)
  go as.DoAuthServer()
  return as
}

func main() {
  server := NewAuthServer()
  res := server.MakeRequest(NewAuthRequest([]string{},"NOOP", nil))
  fmt.Println("MakeRequest complete:", res)
  res = server.MakeRequest(NewAuthRequest([]string{},"LIST",nil))
  fmt.Println("MakeRequest complete:", res)
  res = server.MakeRequest(NewAuthRequest([]string{},"ADD",NewProfileAuthContext("dod")))
  fmt.Println("MakeRequest complete:", res)
  res = server.MakeRequest(NewAuthRequest([]string{"profile/dod"},"ADD",NewProfileAuthContext("farrellit")))
  fmt.Println("MakeRequest complete:", res)
  res = server.MakeRequest(NewAuthRequest([]string{},"LIST",nil))
  fmt.Println("MakeRequest complete:", res)
  res = server.MakeRequest(NewAuthRequest([]string{"profile/dod"},"LIST",nil))
  fmt.Println("MakeRequest complete:", res)
  return
  return
  //////
  baseAuth := make([]AuthContext, 1)
  baseAuth[0] = NewProfileAuthContext("dod")
  mfa := os.Args[1]
  if err := baseAuth[0].Renew(mfa); err != nil {
    panic(err)
  }
  panic(baseAuth[0].Renew(mfa))
  fmt.Println(baseAuth[0].GetCredentials())
}
