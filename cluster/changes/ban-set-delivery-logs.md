### The relay and the control plane log a ban set's first delivery

A relay now logs the first ban set it receives after start (`workeradmit: received the first ban set since start (version N, M banned)`), and every change after it; the unchanged set every management call carries stays silent. Until then the startup line `no saved ban set: workers are refused…` was the last word in the log and read as the current state long after a set arrived. A relay that restarted with a saved set logs when a control plane first confirms it.

The control plane logs its first successful delivery to each relay (`cluster: relay "edge" took the ban set (the first delivery to it from this control plane)`). It logged only failures and recoveries, so "delivery works" and "delivery never ran" read the same.
