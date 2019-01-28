package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
  "github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"
  "net"
)

// this implements credentials.SessionProvider with sts.Credentials source
// it doesn't refresh properly of course ... it would probably need a token for that 
type TempCredentialsProvider struct {
	stsCreds *sts.Credentials
}

func (tcp *TempCredentialsProvider) IsExpired() bool {
	return tcp.stsCreds.Expiration.Before(time.Now())
}

func (tcp *TempCredentialsProvider) Retrieve() (credentials.Value, error) {
	if tcp.IsExpired() {
		return credentials.Value{}, errors.New("Session Token Credentials have expired")
	}
	return credentials.Value{
		AccessKeyID:     aws.StringValue(tcp.stsCreds.AccessKeyId),
		SecretAccessKey: aws.StringValue(tcp.stsCreds.SecretAccessKey),
		SessionToken:    aws.StringValue(tcp.stsCreds.SessionToken),
		ProviderName:    "TempCredentialsProvider",
	}, nil
}

// CredsContext objects provide a way of delegating credentials through a hierarchy.
// credentials.  
type CredsContext interface {
  AddRoles([]string) error // recursive (across objects) function; returns new_role_context.AddRoles(myroles[1:])
  GetMetadataCredentials([]string) (*MetadataResponse, error) // for metadata requests
  Update(*session.Session) error
}

type BaseCredsContext struct {
  name string
  stsCredentials *credentials.Credentials // this is for the metadata endpoint primarily, from .Get() which will autorenew, and .ExpiresAt() tells when it expires if that's missing
	stsSession     *session.Session         // this is a session from the stsCredentials.
	mux            sync.Mutex               // all the following MUST be protected with this mutex
  subContexts map[string]CredsContext // role arn -> credsContext
}

func (bcc *BaseCredsContext) Update(source_sess *session.Session) error {
  /* if source_sess == nil {
    return fmt.Errorf("%s: couldn't update: source_sess was nil", bcc.name)
  } */
  credentials := stscreds.NewCredentials(source_sess,bcc.name)
  sess, err := session.NewSession(&aws.Config{Credentials: credentials})
  if err != nil {
    return err
  }
  bcc.mux.Lock()
  bcc.stsSession = sess
  bcc.stsCredentials = credentials
  bcc.mux.Unlock()
  return bcc.UpdateChildren()
}

func (bcc *BaseCredsContext) UpdateChildren() error {
  if bcc.stsSession == nil {
    return nil
  }
  children := make([]CredsContext,len(bcc.subContexts))
  i:=0
  bcc.mux.Lock()
  for _, child := range bcc.subContexts {
    children[i] = child
  }
  bcc.mux.Unlock()
  for _, child := range children {
    if err := child.Update(bcc.stsSession); err != nil {
      return err
    }
  }
  return nil
}

func (bcc *BaseCredsContext) AddRoles(roles []string) error {
  if len(roles) == 0 {
    return nil
  }
  first_role := roles[0]
  bcc.mux.Lock()
  existing_role_cxt, ok := bcc.subContexts[first_role]
  bcc.mux.Unlock()
  if ok {
    return existing_role_cxt.AddRoles(roles[1:])
  }
  new_context := &BaseCredsContext{
      name: first_role,
      subContexts:   make(map[string]CredsContext),
  }
  if err := new_context.Update(bcc.stsSession); err != nil {
    return fmt.Errorf("Couldn't update session for new role '%s': %s", first_role, err.Error())
  }
	stsc := sts.New(new_context.stsSession)
	out, err := stsc.GetCallerIdentity(&sts.GetCallerIdentityInput{}) // idk if I love this sync call, but it proves we have assumed for sure
  if err != nil {
    return fmt.Errorf("Couldn't GetCallerIdentity on role %s: %s", new_context.name, err.Error())
  }
	fmt.Fprintln(os.Stderr, out)
  bcc.mux.Lock()
  bcc.subContexts[first_role] = new_context
  bcc.mux.Unlock()
  return new_context.AddRoles(roles[1:])
}

/* //// ProfileCredsContext /////

This type represents a profile named in a configuration file,
with, or without, mfa, and is a specific implementation of what should probably be an interface
( "BaseCredsContext" perhaps ).  It's primary distinction is having the top level session that is not
provided for by a previous

*/
type ProfileCredsContext struct {
  BaseCredsContext
	mfa_serial     string
  sourceSession *session.Session // we only need this here I guess
}

func (pcc *ProfileCredsContext) GetMFASerial() (string, error) {
	if pcc.mfa_serial != "" {
		return pcc.mfa_serial, nil
	}
	iamc := iam.New(pcc.sourceSession)
	if err := iamc.ListMFADevicesPages(
		&iam.ListMFADevicesInput{},
		func(out *iam.ListMFADevicesOutput, more bool) bool {
			if len(out.MFADevices) > 0 {
				pcc.mfa_serial = aws.StringValue(out.MFADevices[0].SerialNumber)
				return false
			}
			return more
		},
	); err != nil {
		return "", err
	}
	return pcc.mfa_serial, nil
}


func (pcc *ProfileCredsContext) STSSession(token string) error {
	input := &sts.GetSessionTokenInput{
		DurationSeconds: aws.Int64(129600),
	}
	if len(token) > 0 {
		mfa_serial, err := pcc.GetMFASerial()
		if err != nil {
			return err
		}
		if len(mfa_serial) == 0 {
			return errors.New("Couldn't Get MFA Credentials: Token provided but couldn't find MFA Device under source Session")
		}
		input.SerialNumber = aws.String(mfa_serial)
		input.TokenCode = aws.String(token)
	}
	stsc := sts.New(pcc.sourceSession)
	output, err := stsc.GetSessionToken(input)
	if err != nil {
    return err
  }
  creds := credentials.NewCredentials(&TempCredentialsProvider{output.Credentials})
	sess,err := session.NewSession( pcc.sourceSession.Config, &aws.Config{ Credentials: pcc.stsCredentials},)
  if err != nil {
    return err
  }
  pcc.mux.Lock()
  pcc.stsCredentials = creds
	pcc.stsSession = sess
  pcc.mux.Unlock()
	return pcc.UpdateChildren()
}

////// CredentialsManager handles sets of creds contexts hierarchies

// it's responsible for handling profile web requests too

type CredsManager struct {
	mux      sync.Mutex
	profiles map[string]*ProfileCredsContext
}

func (cm *CredsManager)Allowed(r *http.Request) (allowed bool) {
  allowed = false
  host, port, err := net.SplitHostPort(r.RemoteAddr)
  if err != nil {
    panic(err)
  }
  if host == "169.254.169.254" || host == "127.0.0.1" || host == "::1" { // local request
   allowed = true
  }
  defer func() {
    if !allowed {
      fmt.Fprintf(os.Stderr, "%s - Host %s port %s forbidden.\n", r.RemoteAddr, host, port)
    }
  }()
  //todo: allow docker selectively or map docker matches somehow 
  // (expose underlying docker query format?) to decide whether to allow
  return
}

func NewCredsManager() (cm *CredsManager) {
	cm = new(CredsManager)
	cm.profiles = make(map[string]*ProfileCredsContext, 0)
	return
}

func (cm *CredsManager) AddProfile(pcc *ProfileCredsContext) error {
	cm.mux.Lock()
	defer cm.mux.Unlock()
	if _, ok := cm.profiles[pcc.name]; ok {
		return fmt.Errorf("Profile '%s' already exists in credentials manager", pcc.name)
	}
	cm.profiles[pcc.name] = pcc
	return nil
}

func (cm *CredsManager) ListProfiles() (profiles []string) {
	cm.mux.Lock()
	defer cm.mux.Unlock()
	profiles = make([]string, len(cm.profiles))
	i := 0
	for k, _ := range cm.profiles {
		profiles[i] = k
		i++
	}
	return
}

func (cm *CredsManager) GetProfile(name string) (pcc *ProfileCredsContext) {
	cm.mux.Lock()
	defer cm.mux.Unlock()
	return cm.profiles[name]
}

func (cm *CredsManager) GetProfileRequest(w http.ResponseWriter, r *http.Request, payload []byte, profilename string, chain bool) (pcc *ProfileCredsContext) {
	pcc = cm.GetProfile(profilename)
	if !chain {
		if pcc == nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintln(w, "No such profile", profilename, "has yet been loaded.  This does not necessarily mean it is not defined, and will be loaded automatically if used for a role")
			return
		}
		result := new(struct{ Name string }) // more fields? separate with ;
		result.Name = pcc.name
		if data, err := json.Marshal(result); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "Couldn't marshal result (this is a server-side programming error):", err.Error)
		} else {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, string(data))
		}
	}
	return
}

func (cm *CredsManager) HandleProfileRequest(w http.ResponseWriter, r *http.Request) {
  if ! cm.Allowed(r) {
    w.WriteHeader(http.StatusForbidden)
    fmt.Fprintln(w, r.RemoteAddr)
    return
  }
	payload, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Failed to load payload from request:", err.Error())
		return
	}
	// POST /profiles/<profile name>/roles {"Roles": [ "aws:arn:iam:..." ... ] , "Token": "123456" `optional` }
	// we'd auth each role in turn
	//   -> assume new role under profile, add to list, with current sts credentials (or with new sts creds with token)
	profileRoleRegex := regexp.MustCompile("^/profiles/(?P<profile_name>.+)/roles/*$")
	if res := profileRoleRegex.FindStringSubmatch(r.URL.Path); res != nil {
		if r.Method == "POST" {
			cm.PostProfileRole(w, r, payload, res[1], false)
			return
		} else {
			w.WriteHeader(http.StatusNotImplemented)
			fmt.Fprintln(w, "this endpoint supports the POST method only")
			return
		}
	}
	// POST /profiles/<profile name> {"Token": "123456" `optional` }
	//   -> add new profile to list, get sts credentials (optionally with token)
	// we read this once for chaining
	profileRegex := regexp.MustCompile("^/profiles/(?P<profile_name>.+)$")
	if res := profileRegex.FindStringSubmatch(r.URL.Path); res != nil {
		if r.Method == "POST" {
			cm.PostProfileHandler(w, r, payload, res[1], false)
			return
		} else if r.Method == "GET" {
			cm.GetProfileRequest(w, r, payload, res[1], false)
			return
		} else {
			w.WriteHeader(http.StatusNotImplemented)
			fmt.Fprintln(w, "this endpoint supports the POST method only")
			return
		}
	}
}

func (cm *CredsManager) PostProfileRole(w http.ResponseWriter, r *http.Request, payload []byte, profilename string, chain bool) (result bool) {
	data := new(struct {
		Roles []string
		Token string
	})
	if err := json.Unmarshal(payload, data); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "This endpoint requires a data payload that is valid JSON.  The request body failed to unmarshal: %s", err.Error())
		return
	}
	var pcc *ProfileCredsContext
	if pcc = cm.GetProfile(profilename); pcc == nil {
		// add it if it doesn't exist
		if cm.PostProfileHandler(w, r, payload, profilename, true) == false {
			return // PostProfileHandler handled our errors already
		}
		pcc = cm.GetProfile(profilename) // this is guaranteed to work now I think
	} else {
    if data.Token != "" {
      // we only refresh if we have a new token ( otherwise lack of token might refresh atop a cached creds from token)
		  if cm.PostProfileHandler(w, r, payload, profilename, true) == false {
        return
      }
    }
	}
	// add use existing stsCredentials to assume role(s) in turn (error clearly if expired or intermediate role fails)
	err := pcc.AddRoles(data.Roles)
  if err != nil {
    w.WriteHeader(http.StatusInternalServerError)
    fmt.Fprintln(w,"Failed to add provided roles:", err.Error())
    return
  }
  result = true
  if !chain {
    fmt.Fprintln(w,"Roles Added")
  }
	return
}

// return value here is for chaining.
// it is asumed that `true` means no error, w and r have not been altered
func (cm *CredsManager) PostProfileHandler(w http.ResponseWriter, r *http.Request, payload []byte, profilename string, chain bool) (result bool) {
	result = false
	// given a profile name, auth and store in my CredsContext
	data := new(struct{ Token string })
	if err := json.Unmarshal(payload, data); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "This endpoint requires a data payload that is valid JSON.  The request body failed to unmarshal: %s", err.Error())
		return
	}
	// fmt.Fprintf(os.Stderr, "POST to profile name '%s' payload is:\n%s\nata is %s\n", profilename, payload, data)
  var pcc *ProfileCredsContext
  var already_added bool // flag so we know not to add to cm.Profiles again.
  if pcc = cm.GetProfile(profilename); pcc == nil {
    already_added = false
    // okay, it doesn't exist already, continue
	  profile_session, err := session.NewSessionWithOptions(session.Options{Profile: profilename})
	  if err != nil {
		  w.WriteHeader(http.StatusInternalServerError)
		  fmt.Fprintf(w, "Failed to load session from profile '%s': '%s'\n", profilename, err.Error())
		  return
	  }
	  pcc = &ProfileCredsContext{
		  BaseCredsContext: BaseCredsContext{
        name:          profilename,
        subContexts:   make(map[string]CredsContext),
      },
      sourceSession: profile_session,
	  }
  } else {
    // if it exists already we have only to update the session token and kickoff an update to the tree of roles to update their sessions as well
    already_added = true
  }
	if data.Token != "" {
		mfa_serial, err := pcc.GetMFASerial()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "Couldn't list mfa devices:", err.Error())
			return
		} else if mfa_serial == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "Bad Request: MFA Token provided, but no MFA Device Serial could be found under the profile.")
			return
		}
	}
	if err := pcc.STSSession(data.Token); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Failed to get session credentials:", err.Error())
		return
	}
	fmt.Fprintln(os.Stderr, pcc.stsCredentials) // TODO: remove this dump of creds!
  if ! already_added {
	  if err := cm.AddProfile(pcc); err != nil {
		  w.WriteHeader(http.StatusInternalServerError)
		  fmt.Fprintln(w, "Failed to add profile to credsManager:", err.Error())
		  return
	  }
  }
	result = true
	if !chain { // chaining requires we not write ot our end result
    if ! already_added {
		  w.WriteHeader(http.StatusCreated)
    } else {
      w.WriteHeader(http.StatusOK)
    }
	}
  fmt.Fprintf(os.Stderr, "%#v: result %s already_added %b\n", pcc, result, already_added)
	return // success! result has been set to true already.
}

func main() {
	if os.Getenv("AWS_SDK_LOAD_CONFIG") == "" {
		panic(errors.New("AWS_SDK_LOAD_CONFIG _must_ be set in the environment for this to work."))
		// todo: could we re-exec ourselves I wonder?  Setting with os.Setenv doesn't seem to be enough.
	}
	cm := NewCredsManager()
	http.HandleFunc("/profiles/", cm.HandleProfileRequest)
	panic(http.ListenAndServe(":8081", nil))
}

// MetadtatResponse 

type MetadataResponse struct {
  Code string
  LastUpdated string
  Type string // "AWS-HMAC"
  AccessKeyId string
  SecretAccessKey string
  Token string
  Expiration string // "2017-05-17T15:09:54Z"
}

func (bcc *BaseCredsContext)GetMetadataCredentials(path []string) (*MetadataResponse, error) {
  if len(path) > 0 {
    bcc.mux.Lock()
    subc, ok := bcc.subContexts[path[0]]
    bcc.mux.Unlock()
    if ok {
      return subc.GetMetadataCredentials(path[1:])
    } else {
      return nil, fmt.Errorf("Role %s not found under %s", path[0], bcc.name)
    }
  }
  /* todo: debug
  vexp, err := bcc.stsCredentials.ExpiresAt()
  if err != nil { // TODO: make this work for profiles if it doesn't already, so they can be exposed too if desired
    return nil, fmt.Errorf("Role %s: Failed to get stsCredentials.ExpiresAt : %s", bcc.name, err.Error())
  }
  */
  v, err := bcc.stsCredentials.Get()
  if err != nil {
    return nil, err
  }
  time_format := "2006-01-02T15:04:05Z"
  return &MetadataResponse{
    Code: "SUCCESS",
    LastUpdated: time.Now().UTC().Format(time_format), //How might we know this ... ?
    Type: "AWS-HMAC",
    AccessKeyId: v.AccessKeyID,
    SecretAccessKey: v.SecretAccessKey,
    Token: v.SessionToken,
    Expiration: time.Now().UTC().Format(time_format), //vexp.Format(time_format),
  }, nil
}

