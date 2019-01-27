package main

import (
	/* we only need this if we're gonna read the creds file(s) ourselves.
	"github.com/go-ini/ini"
	"github.com/yookoala/realpath"
	*/
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
)

// regardless of what kind of CredsContext it is, a CredsContext can AddRole()

type CredsContext interface {
	AddRole(role string) // use current stsCredentials to add a new Role or replace an existing Role
}

// profile creds contexts provides top level profile based creds,
// with, or without, mfa.

type ProfileCredsContext struct {
	sourceSession *session.Session // thinking about how the STS session is managed
	mfa_serial    string
	stsSession    *session.Session // this comes from sourceSession I guess?  For assuming subsequent roles?
	// probably, an interface would be the easiest way to make credentials delivery work the same with profile or role
	stsCredentials *sts.Credentials
	name           string
	// SubContexts     []*CredsContext
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
  fmt.Fprintln(os.Stderr,input)
	output, err := stsc.GetSessionToken(input)
	if err == nil {
		pcc.stsCredentials = output.Credentials
	}
	return err
}

////// CredentialsManager handles sets of creds contexts hierarchies

// how to serve credentials to all the various request goroutines?
// need to handle concurrency, probably with channel request/response
// but we have to be congnizant of blocking api calls.
type CredsManager struct {
	profiles []*ProfileCredsContext
}

/* todo.  This isn't strictly necessary but its awefully convenient
func CredentialFileSessions(path string) (sessions []*session.Session, err error) {
  content := ini.Load(realpath.Realpath(path))
  sessions = make([]*session.Session,0)
  for sect := content.Sections():
    print sect
}
*/

func authProfile(w http.ResponseWriter, r *http.Request) {
	// POST /profiles/<profile name> {"Token": "123456" `optional` }
	//   -> add new profile to list, get sts credentials (optionally with token)
	authProfileRegex := regexp.MustCompile("^/profiles/(?P<profile_name>.+)$")
	if res := authProfileRegex.FindStringSubmatch(r.URL.Path); res != nil {
		AddAuthProfile(w, r, res[1])
		return
	}
	// POST /profiles/<profile name>/roles {"Role": "aws:arn:iam:...", "Token": "123456" `optional` }
	//   -> assume new role under profile, add to list, with current sts credentials (or with new sts creds with token)
	// authProfileRoleRegex := regexp.MustCompile("^/profiles/(?P<profile_name>.+)/roles$")
}

func AddAuthProfile(w http.ResponseWriter, r *http.Request, profilename string) {
	// given a profile name, auth and store in my CredsContext
	if r.Method != "POST" {
		w.WriteHeader(http.StatusNotImplemented)
		fmt.Fprintln(w, "this endpoint supports the POST method only")
		return
	}
	payload, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Failed to load payload from request:", err.Error())
		return
	}
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
	pcc := ProfileCredsContext{
		sourceSession: profile_session,
		name:          profilename,
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
	// todo: add to shared credentialsManager
}

func main() {
	if os.Getenv("AWS_SDK_LOAD_CONFIG") == "" {
		panic(errors.New("AWS_SDK_LOAD_CONFIG _must_ be set in the environment for this to work."))
		// todo: could we re-exec ourselves I wonder?  Setting with os.Setenv doesn't seem to be enough.
	}
	http.HandleFunc("/profiles/", authProfile)
	panic(http.ListenAndServe(":8081", nil))
}
