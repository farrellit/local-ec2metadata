package main

import (
  "github.com/farrellit/local-ec2metadata/authcontext"
  "fmt"
)

func main() {
  server := authcontext.NewAuthServer()
  res := server.MakeRequest(authcontext.NewAuthRequest([]string{},"NOOP", nil))
  fmt.Println("MakeRequest complete:", res)
  res = server.MakeRequest(authcontext.NewAuthRequest([]string{},"LIST",nil))
  fmt.Println("MakeRequest complete:", res)
  res = server.MakeRequest(authcontext.NewAuthRequest([]string{},"ADD",NewProfileAuthContext("dod")))
  fmt.Println("MakeRequest complete:", res)
  res = server.MakeRequest(authcontext.NewAuthRequest([]string{"profile/dod"},"ADD",NewProfileAuthContext("farrellit")))
  fmt.Println("MakeRequest complete:", res)
  res = server.MakeRequest(authcontext.NewAuthRequest([]string{},"LIST",nil))
  fmt.Println("MakeRequest complete:", res)
  res = server.MakeRequest(authcontext.NewAuthRequest([]string{"profile/dod"},"LIST",nil))
  fmt.Println("MakeRequest complete:", res)
  res = server.MakeRequest(authcontext.NewAuthRequest([]string{"profile/dod","profile/farrellit"},"CREDS",nil))
  fmt.Println("MakeRequest complete:", res)
  res = server.MakeRequest(authcontext.NewAuthRequest([]string{"profile/dod"},"RENEW","123456"))
  fmt.Println("MakeRequest complete:", res)
  return
}
