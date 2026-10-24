### The provider's client secret stays out of every sink

`client_secret` (the token a browser confirms a charge with) is marked `sensitive` on both responses that return it. The response still carries it; telemetry and the request event stream no longer write it.
