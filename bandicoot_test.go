package main

import (
  _ "github.com/Sirupsen/logrus"
  "github.com/fsouza/go-dockerclient"
  "testing"
)

func TestAllowPort(t *testing.T) {
  const bandicootNamespace = ""
  labels := map[string]string{
    "io.bandicoot.rules": `{
      "input": {
        "https": {
          "destinationPort": 443,
          "match": "conntrack",
          "connectionStates": [
            "NEW",
            "ESTABLISHED"
          ],
          "target": "ACCEPT",
          "protocol": "tcp"
        }
      }
    }`,
  }

  config := docker.Config{Labels: labels}
  container := docker.Container{Config: &config}
  event := docker.APIEvents{Status: "start"}
  expectedOutput := `iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT -m comment --comment "Bandicoot: https"`

  output, err := generateIpTablesRules(&container, event.Status)

  if err != nil {
    t.Fatalf("Error received %v", err)
  }

  if output != expectedOutput {
    t.Fatalf("Error output:\n\t%v\nDid not match expected:\n\t%v\n", output, expectedOutput)
  }
}
