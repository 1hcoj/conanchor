package ledger

type Backend string

const (
	BackendMock Backend = "mock"
	BackendBesu Backend = "besu"
)

type Config struct {
	Backend        Backend
	DataDir        string
	BesuRPCURL     string
	BesuChainID    uint64
	BesuContract   string
	BesuPrivateKey string
	BesuKeyFile    string
}

func NewFromConfig(cfg Config) (Ledger, error) {
	switch cfg.Backend {
	case "", BackendMock:
		return NewMockLedger(cfg.DataDir)
	case BackendBesu:
		return NewBesuLedger(cfg)
	default:
		return nil, ErrUnsupportedBackend{Backend: string(cfg.Backend)}
	}
}

type ErrUnsupportedBackend struct{ Backend string }

func (e ErrUnsupportedBackend) Error() string { return "unsupported ledger backend: " + e.Backend }
