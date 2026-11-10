### The event's referrer loses its query string; UTM values are bounded

An event's `referrer` is now the referring page's scheme, host and path only: its query string, fragment and user info (which can carry an address or a token from a personalised link) no longer reach Brevo, and a referrer that is no absolute URL is left out. UTM parameter names and values are cut at 200 characters. A Brevo segment that matched on a referrer's query string no longer matches.
