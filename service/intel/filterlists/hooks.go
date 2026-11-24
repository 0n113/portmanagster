package filterlists

import "sync"

var (
	listsUpdatedHooksLock sync.Mutex
	listsUpdatedHooks     []func()
)

// OnListsUpdated registers fn to be called after each successful update of
// the filter lists, once the list index and the bloom filters are ready.
// fn must not block.
func OnListsUpdated(fn func()) {
	listsUpdatedHooksLock.Lock()
	defer listsUpdatedHooksLock.Unlock()

	listsUpdatedHooks = append(listsUpdatedHooks, fn)
}

func runListsUpdatedHooks() {
	listsUpdatedHooksLock.Lock()
	hooks := make([]func(), len(listsUpdatedHooks))
	copy(hooks, listsUpdatedHooks)
	listsUpdatedHooksLock.Unlock()

	for _, fn := range hooks {
		fn()
	}
}
