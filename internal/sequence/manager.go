package sequence

import "sync"

type Manager struct {
	mu           sync.Mutex
	globalSeq    uint64
	containerSeq map[string]uint64
}

func NewManager() *Manager {
	return &Manager{containerSeq: make(map[string]uint64)}
}

func (m *Manager) Next(containerInstanceID string) (globalSeq uint64, containerSeq uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.globalSeq++
	m.containerSeq[containerInstanceID]++
	return m.globalSeq, m.containerSeq[containerInstanceID]
}
