### The relay's identity and CA are written whole or not at all

The relay key and certificate and the CA key and certificate were written with plain file writes, so a disk filling up during the first start could leave a truncated key; the next start then refused the half-written pair, and the operator following the message lost the identity. Each file is now written to a temp file, synced and renamed into place, key first, so a failed write leaves nothing and the next start mints a fresh pair. The worker's own key and certificate already were.
