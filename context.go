package main


import (
  "github.com/farrellit/local-ec2metadata/authcontext"
  "fmt"
  "strings"
  "bufio"
  "os"
)

func main() {
  server := authcontext.NewAuthServer()
  res := server.MakeRequest(authcontext.NewAuthRequest([]string{},"NOOP", nil))
  fmt.Println("MakeRequest NOOP complete:", res)
  res = server.MakeRequest(authcontext.NewAuthRequest([]string{},"LIST",nil))
  fmt.Println("MakeRequest LIST complete:", res)
  res = server.MakeRequest(authcontext.NewAuthRequest([]string{},"ADD",authcontext.NewProfileAuthContext("dod")))
  fmt.Println("MakeRequest ADD PorfileAuthContext(['dod') complete:", res)
  res = server.MakeRequest(authcontext.NewAuthRequest([]string{"profile.dod"},"ADD",authcontext.NewProfileAuthContext("farrellit")))
  fmt.Println("MakeRequest ADD under profile.dod PorfileAuthContext(['dod') complete:", res)
  res = server.MakeRequest(authcontext.NewAuthRequest([]string{},"LIST",nil))
  fmt.Println("MakeRequest LIST complete:", res)
  res = server.MakeRequest(authcontext.NewAuthRequest([]string{"profile.dod"},"LIST",nil))
  fmt.Println("MakeRequest LIST profile.dod complete:", res)
  res = server.MakeRequest(authcontext.NewAuthRequest([]string{"profile.dod"},"CREDS",nil))
  fmt.Println("MakeRequest CREDS profile.dod complete:", res)
  fmt.Printf("MFA Token? for profile.dod ?")
  token, err := bufio.NewReader(os.Stdin).ReadString('\n')
  token = strings.TrimSpace(token)
  if err != nil {
    panic(err)
  }
  fmt.Println(token)
  res = server.MakeRequest(authcontext.NewAuthRequest([]string{"profile.dod"},"RENEW",token))
  fmt.Println("MakeRequest RENEW profile.dod complete:", res)
  res = server.MakeRequest(authcontext.NewAuthRequest([]string{"profile.dod"},"CREDS",nil))
  fmt.Println("MakeRequest CREDS profile.dod complete:", res)
  return
}
