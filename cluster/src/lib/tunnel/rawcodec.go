package tunnel

import (
	"fmt"

	"google.golang.org/grpc/mem"
)

// rawCodecName is what the forwarded call announces on the wire.
//
// "proto", and that is not a lie: the bytes travelling through ARE proto, the
// relay simply never decodes them. The name matters because ForceCodecV2 sets
// the content-subtype from it, and the WORKER picks its codec by that subtype
// — announce anything else and the worker reaches for this codec to decode its
// own real messages, which is a failure that reads like a client bug.
const rawCodecName = "proto"

// Frame is one message, still encoded.
//
// The relay must not know what the workers speak — that is the property that
// lets one plugin serve compile workers and headless browsers — so the proxy
// never unmarshals. It moves bytes and copies the trailers.
type Frame struct {
	Data []byte
}

// rawCodec passes payloads through untouched.
//
// NOT REGISTERED, deliberately. gRPC's codec registry is process-wide, so
// registering this under "proto" would replace the real codec for every
// service in the binary — the relay's own management API, the worker's own
// services, every client either of them holds. Instead it is handed to the one
// call that needs it, through ForceCodecV2 / ForceServerCodecV2, which bypass
// the registry entirely.
type rawCodec struct{}

func (rawCodec) Name() string { return rawCodecName }

func (rawCodec) Marshal(v any) (mem.BufferSlice, error) {
	f, ok := v.(*Frame)
	if !ok {
		return nil, fmt.Errorf("tunnel: the raw codec was handed a %T; it only moves *Frame", v)
	}
	return mem.BufferSlice{mem.SliceBuffer(f.Data)}, nil
}

func (rawCodec) Unmarshal(data mem.BufferSlice, v any) error {
	f, ok := v.(*Frame)
	if !ok {
		return fmt.Errorf("tunnel: the raw codec was handed a %T; it only moves *Frame", v)
	}
	f.Data = data.Materialize()
	return nil
}
