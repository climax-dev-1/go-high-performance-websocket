package relay

import "sync"

// Hub is a thread-safe registry of live Connections. It exists mainly to
// support graceful shutdown (CloseAll) and for introspection/metrics.
type Hub struct {
	mu    sync.RWMutex
	conns map[string]*Connection
}

func NewHub() *Hub {
	return &Hub{conns: make(map[string]*Connection)}
}

func (h *Hub) Add(c *Connection) {
	h.mu.Lock()
	h.conns[c.id] = c
	h.mu.Unlock()
}

func (h *Hub) Remove(c *Connection) {
	h.mu.Lock()
	delete(h.conns, c.id)
	h.mu.Unlock()
}

// CloseAll triggers close() on every connection. Each connection handles its
// own goroutine teardown. Safe to call multiple times.
func (h *Hub) CloseAll() {
	h.mu.RLock()
	conns := make([]*Connection, 0, len(h.conns))
	for _, c := range h.conns {
		conns = append(conns, c)
	}
	h.mu.RUnlock()
	for _, c := range conns {
		c.close()
	}
}
