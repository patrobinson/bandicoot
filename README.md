Bandicoot
----

Still under development.

Reads labels from docker containers to determine what ports to open via iptables. The label namespace is "io.bandicoot.rules":

Example label:

```
{
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
}
```

By running bandicoot locally and starting a container with this label, bandicoot will open port 443 for connections from any host.

The listed attributes are currently the only ones supported.
