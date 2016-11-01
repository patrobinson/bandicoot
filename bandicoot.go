package main

import (
	"encoding/json"
	"errors"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/fsouza/go-dockerclient"
	iptables "github.com/coreos/go-iptables/iptables"
	"strings"
	"time"
	"strconv"
)

const workerTimeout = 180 * time.Second

type handler interface {
	Handle(*docker.APIEvents) error
}

type dockerRouter struct {
	handlers      map[string][]handler
	dockerClient  *docker.Client
	listener      chan *docker.APIEvents
	workers       chan *worker
	workerTimeout time.Duration
}

type iptablesRule struct {
	action   string
	chain    string
	rulespec [][]string
}

func dockerEventsRouter(bufferSize int, workerPoolSize int, dockerClient *docker.Client,
	handlers map[string][]handler) (*dockerRouter, error) {
	workers := make(chan *worker, workerPoolSize)
	for i := 0; i < workerPoolSize; i++ {
		workers <- &worker{}
	}

	dockerRouter := &dockerRouter{
		handlers:      handlers,
		dockerClient:  dockerClient,
		listener:      make(chan *docker.APIEvents, bufferSize),
		workers:       workers,
		workerTimeout: workerTimeout,
	}

	return dockerRouter, nil
}

func (e *dockerRouter) start() error {
	go e.manageEvents()
	return e.dockerClient.AddEventListener(e.listener)
}

func (e *dockerRouter) stop() error {
	if e.listener == nil {
		return nil
	}
	return e.dockerClient.RemoveEventListener(e.listener)
}

func (e *dockerRouter) manageEvents() {
	for {
		event := <-e.listener
		timer := time.NewTimer(e.workerTimeout)
		gotWorker := false
		// Wait until we get a free worker or a timeout
		// there is a limit in the number of concurrent events managed by workers to avoid resource exhaustion
		// so we wait until we have a free worker or a timeout occurs
		for !gotWorker {
			select {
			case w := <-e.workers:
				if !timer.Stop() {
					<-timer.C
				}
				go w.doWork(event, e)
				gotWorker = true
			case <-timer.C:
				log.Infof("Timed out waiting.")
			}
		}
	}
}

type worker struct{}

func (w *worker) doWork(event *docker.APIEvents, e *dockerRouter) {
	defer func() { e.workers <- w }()
	if handlers, ok := e.handlers[event.Status]; ok {
		log.Infof("Processing event: %#v", event)
		for _, handler := range handlers {
			if err := handler.Handle(event); err != nil {
				log.Errorf("Error processing event %#v. Error: %v", event, err)
			}
		}
	}
}

type dockerHandler struct {
	handlerFunc func(event *docker.APIEvents) error
}

func (th *dockerHandler) Handle(event *docker.APIEvents) error {
	return th.handlerFunc(event)
}

func commentForRule(description string) string {
	return fmt.Sprintf(`"Bandicoot: %v"`, description)
}

func generateIpTablesRules(container *docker.Container, status string) (iptablesRule, error) {
	var returnValue iptablesRule
	const bandicootNamespace = "io.bandicoot.rules"
	allowed, ok := container.Config.Labels[bandicootNamespace]

	switch status {
	case "start":
		returnValue.action = "Append"
	case "die":
		returnValue.action = "Delete"
	default:
		return returnValue, errors.New("unexpected event received")
	}

	if ok {
		var label map[string]interface{}
		err := json.Unmarshal([]byte(allowed), &label)
		if err != nil {
			log.Fatal(err)
		}

		for k, v := range label {
			returnValue.chain = strings.ToUpper(k)
			for desc, o := range v.(map[string]interface{}) {
				options := o.(map[string]interface{})
				cS := options["connectionStates"].([]interface{})
				connectionStates := make([]string, len(cS))
				for i := range cS {
					connectionStates[i] = cS[i].(string)
				}
				returnValue.rulespec = append(returnValue.rulespec,
					[]string{
						"-p",
						options["protocol"].(string),
						"--dport",
						strconv.FormatFloat(options["destinationPort"].(float64), 'f', 0, 64),
						"-m",
						options["match"].(string),
						"--ctstate",
						strings.Join(connectionStates, ","),
						"-j",
						options["target"].(string),
						"-m",
						"comment",
						"--comment",
						commentForRule(desc),
				})
			}
		}
	}
	return returnValue, nil
}

func manageIpTablesRules(container *docker.Container, status string) error {
	const protocol = iptables.ProtocolIPv4
	ipt, err := iptables.NewWithProtocol(protocol)
	if err != nil {
		log.Fatal(err)
	}


	output, err := generateIpTablesRules(container, status)
	if err == nil {
		log.Infof("Processing %v rules", len(output.rulespec))
		for i := range output.rulespec {
			if output.action == "Append" {
				err = ipt.Append("filter", output.chain, output.rulespec[i]...)
			} else {
				err = ipt.Delete("filter", output.chain, output.rulespec[i]...)
			}
			if err != nil {
				log.Error("Unable to add chain rule: %v", err)
			} else {
				log.Infof("Added rule: %v", output.rulespec[i])
			}
		}
	} else {
		log.Error("Failed to generate iptables rule %v", err)
	}

	return err
}

func main() {
	endpoint := "unix:///var/run/docker.sock"
	dockerClient, err := docker.NewClient(endpoint)
	if err != nil {
		log.Fatal(err)
	}

	startFn := func(event *docker.APIEvents) error {
		var err error
		container, err := dockerClient.InspectContainer(event.ID)
		if err != nil {
			log.Fatal(err)
		}

		manageIpTablesRules(container, event.Status)

		return nil
	}

	startStopHandler := &dockerHandler{
		handlerFunc: startFn,
	}

	handlers := map[string][]handler{"start": []handler{startStopHandler}, "die": []handler{startStopHandler}}
	router, err := dockerEventsRouter(5, 5, dockerClient, handlers)
	if err != nil {
		log.Fatal(err)
	}
	defer router.stop()
	router.start()
	fmt.Println("Waiting events")
	select {}
}
