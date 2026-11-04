# Client address

By default the server identifies a client by the address of the connection, because `X-Forwarded-For` is written by whoever sends the request. Behind an Ingress, that is the Ingress pod for every client. With `--trusted-proxies` (chart value `trustedProxies`, a list), a request whose connection comes from one of those ranges is attributed to the rightmost `X-Forwarded-For` address outside them, after joining every `X-Forwarded-For` header line in order. Proxies such as HAProxy (`option forwardfor`), nginx (`$proxy_add_x_forwarded_for`) and cloud load balancers append the address they saw, so entries the client wrote stay on the left and are never used. A malformed entry stops the search at the last valid one.

The client address is used for sign-in limits and [integration allowed addresses](integrations.md), and is logged as `client` in the [audit log](observability.md#audit-log) when it differs from the connection address. For it to be the real client, every hop has to see it:

- List only the proxies, for example the Ingress controller pods (k3s: `10.42.0.0/16`) and any load balancer in front of them. A range that covers clients lets them pick their own address.
- A LoadBalancer Service with `externalTrafficPolicy: Cluster` replaces the client address with a node address before the Ingress controller sees it. Use `Local` to keep it. In MetalLB, Services sharing an IP (`metallb.io/allow-shared-ip`) must all use the same policy, and with `Local` also the same pod selector, so an Ingress controller sharing its IP with other Services needs its own IP first.
