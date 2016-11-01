Bandicoot
----

Still under development.

Reads labels from docker containers to determine what ports to open via iptables. The label namespace is "io.bandicoot.rules"

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
