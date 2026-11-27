package adminui

import (
	"sync"
	"time"
)

// limiter counts failed logins per key (account or IP address) and blocks
// a key after max failures within window.
type limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	fails  map[string][]time.Time
}

func newLimiter(maxFails int, window time.Duration) *limiter {
	return &limiter{max: maxFails, window: window, fails: make(map[string][]time.Time)}
}

// blocked tells whether one of the keys reached the limit.
func (l *limiter) blocked(now time.Time, keys ...string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		if len(l.recent(k, now)) >= l.max {
			return true
		}
	}
	return false
}

// fail records a failure for each key.
func (l *limiter) fail(now time.Time, keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.fails) > 10_000 {
		for k := range l.fails {
			l.recent(k, now)
		}
	}
	for _, k := range keys {
		l.fails[k] = append(l.recent(k, now), now)
	}
}

// recent drops the failures of a key older than the window.
func (l *limiter) recent(key string, now time.Time) []time.Time {
	list := l.fails[key]
	i := 0
	for i < len(list) && now.Sub(list[i]) >= l.window {
		i++
	}
	list = list[i:]
	if len(list) == 0 {
		delete(l.fails, key)
		return nil
	}
	l.fails[key] = list
	return list
}
