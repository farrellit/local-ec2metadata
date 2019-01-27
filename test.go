package main

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/gorilla/handlers"
	"net"
	"net/http"
	"os"
  "github.com/go-ini/ini"
  "time"
  "errors"
)


// hmm ,this seems like it conflicts with the nice session mgmt 
type CredentialMaterials struct {
  AccessKeyId string
  SecretAccessKey string
  SecurityToken string
  Expiration date.Date
}


type Creds interface {
  GetCredentialMaterials() // return for ec2 credential endpoint, assumption would be implicit to this interface
  GetSession() // return a session assiciated with this credential soruce
  AddSubCred(*Cred)     // a subcredential that can be assumed from this one
  GetSubCreds() []*Cred    // get subcredentials
}

// This struct will represent role or profile based credentials
type GeneralCred struct {
  subCreds []*Cred
  parentCred *Cred // you'll use these creds to renew yourself (possibly causing a cascading effect of reauthenticating, which is why it should be done async)
                   // empty for Profile I guess?  A profile from a role or profile?  That doesn't make sense.
  Role string      // empty for Profile
  Profile string   // empty for Role
  ConfigFile string // empty for Role
  cachedMaterials *CredentialMaterials
}

func NewGeneralCred(profile string,configFile string,parent *Cred,role string) gc*GeneralCred , error {
  gc = new(GeneralCred)
  gc.subCreds=make([]*Cred,0)
  gc.parentCred = parent
  gc.Profile = profile
  gc.ConfigFile = configFile
  return gc, nil //TODO: role and profile are exclusive.
}

func (gc *GeneralCred) GetSubCreds() []*Creds {
  return gc.subCreds
}

func (gc *GeneralCred) AddSubCred(child*Cred) error {
  gc.SubCreds = append(gc.SubCreds,child)
  return nil
}

func (gc *GeneralCred) GetSession() *CredentialMaterials, error {
  if gc.Profile != "" && gc.ConfigFile != "" {
    return ProfileGetCredentials()
  } else if gc.ParentCred != nil && gc.Role != "" {
    return RoleGetCredentials()
  }
  else {
    return nil, errors.New("No profile or role configuration")
  }
}

func (gc *GeneralCred) GetSession() sess *session.Session() {
  
}

func (gc *GeneralCred) RoleGetCredentials cm *CredentialMaterials, error {
  parentcm = gc.ParentCred.GetCredentials()
  default_session := session.Must(session.NewSession())
	stsc := sts.New(default_session, &aws.Config{})
}
func (gc *GeneralCred) RoleGetCredentials cm *CredentialMaterials, error {
  parentcm = gc.ParentCred.GetCredentials()
  default_session := session.Must(session.NewSession())
	stsc := sts.New(default_session, &aws.Config{})
}

// CredForest : top level data struct
// a single thread handling it on a select 
// users send a return chan
type CredForest struct {
  roots []*Creds
  GetCreds  chan *CredRequest
}

type CredRequest struct {
  Response chan []*Creds
}

func CredForestBroker(


func (cf *CredForest)AddProfile(

func GetConfiguredProfiles(config string, credentials string) []*Creds {
  profiles = make([]string)
  cfg, err := ini.Load("path" +"/"+"config")
  if err {
    panic(err)
  }
  for _, sect := range cfg.Sections
  profile = append(proiles,...cfg.Sections())
}


/// web side 


func HandleCreds(w http.ResponseWriter, r *http.Request) {
	ipaddr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		panic(err)
	}
	if ipaddr != "169.254.169.254" {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(r.RemoteAddr))
		return
	}
	fmt.Fprintf(w, "I trust you, %s", ipaddr)
	/*
  default_session := session.Must(session.NewSession())
	stsc := sts.New(default_session, &aws.Config{})
	res, err := stsc.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		panic(err)
	}
	fmt.Fprintln(w, res)
  */
}

func main() {
  os.Setenv("AWS_SDK_LOAD_CONFIG", "true")
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/creds" {
			HandleCreds(w, r)
			return
		}
		inters, err := net.Interfaces()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("500 - failed to list system network interfaces"))
			return
		}
		for _, inter := range inters {
			fmt.Fprintln(w, inter)
			addrs, _ := inter.Addrs()
			for _, addr := range addrs {
				fmt.Fprintln(w, addr)
			}
		}
		networks, err := cli.NetworkList(context.Background(), types.NetworkListOptions{})
		if err != nil {
			panic(err)
		}
		for _, network := range networks {
			fmt.Fprintf(w, "%s %s\n", network.ID[:10], network.Options)
		}
		containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{All: true})
		if err != nil {
			panic(err)
		}
		for _, container := range containers {
			fmt.Fprintln(w, container)
		}

	})
	panic(http.ListenAndServe("169.254.169.254:8000", handlers.LoggingHandler(os.Stderr, http.DefaultServeMux)))
}
