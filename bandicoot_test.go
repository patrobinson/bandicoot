package main

import (
	_ "github.com/Sirupsen/logrus"
	"github.com/fsouza/go-dockerclient"
	"strings"
	"testing"
)

func TestAllowPort(t *testing.T) {
	const bandicootNamespace = ""
	labels := map[string]string{
		"io.bandicoot.rules": `{
      "input": [
        {
          "protocol": "tcp",
          "description": "https",
          "port": 443,
          "source_ip": "0.0.0.0/0"
        }
      ]
    }`,
	}

	config := docker.Config{Labels: labels}
	container := docker.Container{Config: &config}
	event := docker.APIEvents{Status: "start"}
	expectedRuleSpec := []string{"-p", "tcp", "--dport", "443", "--source", "0.0.0.0/0", "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED", "-j", "ACCEPT", "-m", "comment", "--comment", `"Bandicoot: https"`}

	output, err := generateIpTablesRules(&container, event.Status)

	if err != nil {
		t.Fatalf("Error received %v", err)
	}

	if output.chain != "INPUT" {
		t.Fatalf(`Expected chain to be "INPUT"`)
	}

	if output.action != "Append" {
		t.Fatalf(`Expected action to be "Append"`)
	}

	for i := range output.rulespec[0] {
		if output.rulespec[0][i] != expectedRuleSpec[i] {
			t.Log(strings.Join(output.rulespec[0], ","))
			t.Fatalf("Error output:\n\t%v\nDid not match expected:\n\t%v\n", output.rulespec[0][i], expectedRuleSpec[i])
		}
	}
}
