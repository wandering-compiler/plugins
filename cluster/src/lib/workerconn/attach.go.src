package workerconn

import (
	"context"
	"errors"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/plugins/cluster/workerpb"
)

// State is what the relay last said about this worker.
type State int

const (
	// Admitted — attached, and may be given work.
	Admitted State = iota
	// Banned — refused by an operator's ban, and refused again on every
	// reconnect until it is lifted.
	Banned
	// Disconnected — no relay right now; the loop is retrying.
	Disconnected
	// Renewed — the certificate was reissued. Not a connection state, but a
	// transition an operator wants in the log.
	Renewed
)

func (s State) String() string {
	switch s {
	case Admitted:
		return "admitted"
	case Banned:
		return "banned"
	case Renewed:
		return "certificate renewed"
	default:
		return "disconnected"
	}
}

// Config is what a worker needs to join a pool.
type Config struct {
	// RelayAddress is `host:port` of the relay's WORKER-ATTACH listener —
	// where the worker attaches, enrols and renews.
	RelayAddress string

	// RelayFingerprint pins the relay's certificate (lowercase hex SHA-256 of
	// its DER), as handed out with the registration code.
	//
	// The worker verifies the relay for the same reason the relay verifies the
	// worker, and it is not symmetry for its own sake: an impostor relay would
	// be handed this machine's work, and in a pool that compiles somebody's
	// source or fetches somebody's pages, the work IS the secret.
	RelayFingerprint string

	// IdentityDir holds this worker's key (generated on first start, never
	// sent anywhere) and the certificate its relay issued for it. Keep it on a
	// volume: the key IS the worker's identity, and a worker that lost it is a
	// new worker needing a new registration code.
	IdentityDir string

	// RegistrationCode is the one-time code an operator issued for this relay.
	// Used only when IdentityDir holds no valid certificate, so leaving it in
	// a deployment's environment after the first start is harmless.
	RegistrationCode string

	// RenewBefore is how long before expiry the certificate is renewed. Zero
	// renews with a third of its lifetime left.
	RenewBefore time.Duration

	Name     string
	DeviceID string

	// Slots is how many tasks this machine can run at once.
	//
	// A property of the MACHINE, which is why the worker reports it instead of
	// the relay configuring it: one headless browser holds a handful of
	// sessions before it degrades, and that number belongs to the box. The
	// relay's capacity is the sum over its attached workers.
	//
	// Zero means this worker takes no work. Refused at Run rather than
	// defaulted — a silently-1 worker in a pool sized for 4 looks like a
	// capacity bug on the relay, and it is the kind that is only visible under
	// load.
	Slots uint32

	// Readiness, if set, is consulted whenever the worker is asked whether it
	// still wants work, and its answer is sent to the relay when it changes.
	//
	// This is the worker's OWN check — open a tab, touch the disk, whatever it
	// measures — and not an inference from CPU. A wedged engine on a healthy
	// socket is exactly the case a connection-liveness check cannot see.
	// Nil means permanently ready.
	Readiness func() Readiness

	// ReadinessInterval is how often Readiness is consulted. Zero uses a
	// default. Nothing on the relay expires a status, so this is only how
	// quickly a change is noticed, not a heartbeat.
	ReadinessInterval time.Duration

	// TunnelAddress is `host:port` of the relay's WORK listener — a separate
	// port from the one Attach uses, because the two connections carry
	// different things and only one of them exists before enrolment.
	TunnelAddress string

	// RetryInterval between reconnects. Zero uses a sane default.
	RetryInterval time.Duration
	// BannedRetryInterval is longer: a ban is a decision, and hammering a
	// relay that has already refused is noise in somebody's logs. Retried at
	// all because a ban can be lifted, and a worker that exited would need a
	// human to notice and restart it.
	BannedRetryInterval time.Duration
}

func (cfg Config) retry() time.Duration {
	if cfg.RetryInterval <= 0 {
		return 5 * time.Second
	}
	return cfg.RetryInterval
}

func (cfg Config) validateIdentity() error {
	if strings.TrimSpace(cfg.RelayAddress) == "" {
		return errors.New("workerconn: RelayAddress is required")
	}
	if strings.TrimSpace(cfg.RelayFingerprint) == "" {
		// Refused rather than defaulted to "trust any relay": without a pin
		// this worker would hand its work to whoever answered the address.
		return errors.New(
			"workerconn: RelayFingerprint is required — without it this worker cannot tell " +
				"the relay from anything else listening on that address")
	}
	if strings.TrimSpace(cfg.IdentityDir) == "" {
		return errors.New("workerconn: IdentityDir is required — it holds this worker's key, which is its identity")
	}
	return nil
}

// Readiness is what a worker says about its own ability to take work.
type Readiness int

const (
	// Ready — take work.
	Ready Readiness = iota
	// Draining — deliberate. Finish what is running, start nothing new.
	//
	// The reason this exists: without it the only way to stop receiving work
	// was to drop the tunnel, which also killed the sessions already running
	// on it. A worker could not be replaced without losing work in flight.
	Draining
	// Unhealthy — the worker's own check failed.
	Unhealthy
)

func (r Readiness) proto() workerpb.WorkerStatus_Readiness {
	switch r {
	case Draining:
		return workerpb.WorkerStatus_DRAINING
	case Unhealthy:
		return workerpb.WorkerStatus_UNHEALTHY
	default:
		return workerpb.WorkerStatus_READY
	}
}

// Run enrols if it must, keeps the certificate renewed, and attaches to the
// relay — reattaching until ctx ends.
//
// onState is called on every transition, including repeats after a reconnect —
// the caller decides what is worth logging. It must not block.
//
// It returns ErrNeedsRegistration when the worker has no usable certificate
// and no code to get one with, ErrInvalidClaim when it would enrol under a
// name or device id the registry cannot record, and the relay's refusal when
// the relay refused the enrolment with a reason: an operator has to act, and
// a loop retrying the impossible would only hide that.
func Run(ctx context.Context, cfg Config, onState func(State)) error {
	if err := cfg.validateIdentity(); err != nil {
		return err
	}
	if cfg.Slots == 0 {
		return errors.New(
			"workerconn: Slots is required — a worker that does not say how much it can " +
				"take is counted as nothing, and a default would be a capacity claim " +
				"this package is not entitled to make on the machine's behalf")
	}
	banned := cfg.BannedRetryInterval
	if banned <= 0 {
		banned = 5 * time.Minute
	}
	if onState == nil {
		onState = func(State) {}
	}

	// Enrolment first, retried while the relay is merely unreachable; a
	// refusal no retry can fix ends Run.
	for {
		err := EnsureEnrolled(ctx, cfg)
		if err == nil {
			break
		}
		if errors.Is(err, ErrNeedsRegistration) || errors.Is(err, ErrInvalidClaim) ||
			refusal.ReasonOf(err) != "" || ctx.Err() != nil {
			return err
		}
		onState(Disconnected)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(cfg.retry()):
		}
	}

	renewCtx, stopRenewing := context.WithCancel(ctx)
	defer stopRenewing()
	go keepRenewed(renewCtx, cfg,
		func(time.Time) { onState(Renewed) },
		func(error) {})

	for {
		if _, err := certificateUsable(cfg); err != nil {
			return err
		}
		wait := cfg.retry()
		if err := attachOnce(ctx, cfg, onState); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if refusal.ReasonOf(err) == refusal.WorkerBanned || status.Code(err) == codes.PermissionDenied {
				onState(Banned)
				wait = banned
			} else {
				onState(Disconnected)
			}
		} else {
			onState(Disconnected)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

func attachOnce(ctx context.Context, cfg Config, onState func(State)) error {
	conn, err := dialAttach(cfg, true)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	stream, err := workerpb.NewWorkerAttachClient(conn).Attach(ctx)
	if err != nil {
		return err
	}
	// Asked BEFORE announcing, and carried in the announcement.
	//
	// The relay credits a worker from the moment it announces, so a readiness
	// that only arrived with the first status left a window — one tick wide,
	// a second by default — in which a machine that came up already draining
	// or already wedged was handed work.
	initial := Ready
	if cfg.Readiness != nil {
		initial = cfg.Readiness()
	}
	if err := stream.Send(&workerpb.WorkerMessage{
		Msg: &workerpb.WorkerMessage_Announce{Announce: &workerpb.AttachReq{
			Name:      cfg.Name,
			DeviceId:  cfg.DeviceID,
			Slots:     cfg.Slots,
			Readiness: initial.proto(),
		}},
	}); err != nil {
		return err
	}

	// Report readiness changes for as long as this attachment lasts. Scoped to
	// the attachment and not to Run, so a reconnect starts a fresh reporter
	// against the new stream rather than writing into a dead one.
	attached, stopReporting := context.WithCancel(ctx)
	defer stopReporting()
	if cfg.Readiness != nil {
		go reportReadiness(attached, stream, cfg, initial)
	}

	for {
		ev, err := stream.Recv()
		if err != nil {
			return err
		}
		if ev.GetAdmitted() != nil {
			onState(Admitted)
		}
	}
}

// reportReadiness sends the worker's own answer whenever it changes.
//
// Only on CHANGE: the relay does not expire a status and nothing is waiting
// for a heartbeat, so repeating an unchanged answer would be traffic that
// tells nobody anything. A send error ends the loop — the stream is gone, and
// the attach loop is already handling that.
func reportReadiness(
	ctx context.Context,
	stream grpc.BidiStreamingClient[workerpb.WorkerMessage, workerpb.AttachEvent],
	cfg Config,
	announced Readiness,
) {
	interval := cfg.ReadinessInterval
	if interval <= 0 {
		interval = time.Second
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()

	// Seeded with what the ANNOUNCEMENT already carried, not with Ready. A
	// worker that announced while draining would otherwise have its first
	// change back to Ready read as no change at all, and it would stay out of
	// the fleet until it happened to go unhealthy and recover.
	last := announced
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			now := cfg.Readiness()
			if now == last {
				continue
			}
			if err := stream.Send(&workerpb.WorkerMessage{
				Msg: &workerpb.WorkerMessage_Status{Status: &workerpb.WorkerStatus{
					Readiness: now.proto(),
				}},
			}); err != nil {
				return
			}
			last = now
		}
	}
}
