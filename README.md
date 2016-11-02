Bandicoot
----

Still under development.

Reads labels from docker containers to determine what ports to open via iptables. The label namespace is "io.bandicoot.rules":

Example label:

```
{
  "input": [
    {
      "protocol": "tcp",
      "description": "https",
      "port": 443
    }
  ]
}
```

By running bandicoot locally and starting a container with this label, bandicoot will open port 443 for connections from any host.

The listed attributes are currently the only ones supported.
