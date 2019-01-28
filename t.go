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
} /// what needs here? everything called on BaseCredsContext in a generic place I think

type BaseCredsContext struct {
  name string
  stsCredentials *sts.Credentials // this is for the metadata endpoint primarily
	stsSession     *session.Session         // this is a session from the stsCredentials.
  sourceSession *session.Session
	mux            sync.Mutex               // all the following MUST be protected with this mutex
  subContexts map[string]*CredsContext // role arn -> credsContext
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
	if err == nil {
		// be on the lookout for a race condition if we ever assume these to be conjoined atomically
		pcc.stsSession = session.Must(session.NewSession(
			pcc.sourceSession.Config,
			&aws.Config{
				Credentials: credentials.NewCredentials(&TempCredentialsProvider{output.Credentials}),
			},
		))
		pcc.stsCredentials = output.Credentials
	}
	return err
}

////// CredentialsManager handles sets of creds contexts hierarchies

// how to serve credentials to all the various request goroutines?
// need to handle concurrency, probably with channel request/response
// but we have to be congnizant of blocking api calls.

type CredsManager struct {
	mux      sync.Mutex
	profiles map[string]*ProfileCredsContext
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
	payload, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Failed to load payload from request:", err.Error())
		return
	}
	// POST /profiles/<profile name>/roles {"Roles": [ "aws:arn:iam:..." ... ] , "Token": "123456" `optional` }
	// we'd auth each role in turn
	//   -> assume new role under profile, add to list, with current sts credentials (or with new sts creds with token)
	profileRoleRegex := regexp.MustCompile("^/profiles/(?P<profile_name>.+)/roles$")
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
		fmt.Fprintf(os.Stderr, "cm.PostProfileRow(): cm.GetProfile '%s' returned nil\n", profilename)
		// add it if it doesn't exist
		if cm.PostProfileHandler(w, r, payload, profilename, true) == false {
			return // we'll let PostProfileHandler handle our errors here
		}
		pcc = cm.GetProfile(profilename) // this is guaranteed to work now I think
	} else {
		// TODO: refresh pcc from token if included
	}
	// add use existing stsCredentials to assume role(s) in turn (error clearly if expired or intermediate role fails)
	source_session := pcc.stsSession
	for _, role_arn := range data.Roles {
		role_session, err := session.NewSession(&aws.Config{Credentials: stscreds.NewCredentials(source_session, role_arn)})
		stsc := sts.New(role_session)
		out, err := stsc.GetCallerIdentity(&sts.GetCallerIdentityInput{})
		fmt.Fprintln(w, out)
		fmt.Fprintln(w, err)
		// todo: storage, etc
		source_session = role_session
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
	fmt.Fprintf(os.Stderr, "POST to profile name '%s' payload is:\n%s\nData is %s\n", profilename, payload, data)
	profile_session, err := session.NewSessionWithOptions(session.Options{Profile: profilename})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Failed to load session from profile '%s': '%s'\n", profilename, err.Error())
		return
	}
	pcc := &ProfileCredsContext{
		BaseCredsContext: BaseCredsContext{
      sourceSession: profile_session,
      name:          profilename,
   },
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
	if err = pcc.STSSession(data.Token); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Failed to get session credentials:", err.Error())
		return
	}
	// todo: remove this!
	fmt.Fprintln(os.Stderr, pcc.stsCredentials)
	if err := cm.AddProfile(pcc); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Failed to add profile to credsManager:", err.Error())
		return
	}
	result = true
	if !chain { // chaining requires we not write ot our end result
		w.WriteHeader(http.StatusCreated)
	}
	return // success!
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
