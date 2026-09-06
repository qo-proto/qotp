package qotp

import (
	"cmp"
	"iter"
	"sync"
)

// =============================================================================
// LinkedMap - Hash map with O(1) operations and order preservation
//
// NOT goroutine-safe. Every instance has exactly one owner that serializes
// access: the send buffer (sender.mu) and receive buffer (receiver.mu).
// Their invariants span the map plus external state (capacity counters,
// generation membership), so synchronization must live in the owner — an
// internal lock could not be widened to cover the composite operations and
// would only add overhead on the per-packet hot path.
//
// For maps shared across goroutines (conn.streams, listener.connMap), use
// sharedLinkedMap below.
//
// Two insertion modes:
// - put(): Maintains insertion order (append to end)
// - putOrdered(): Maintains sorted order (O(1) for in-order arrivals)
// =============================================================================

type linkedMap[K cmp.Ordered, V any] struct {
	items map[K]*lmNode[K, V]
	head  *lmNode[K, V] // Sentinel head node
	tail  *lmNode[K, V] // Sentinel tail node
	len   int
}

type lmNode[K cmp.Ordered, V any] struct {
	key   K
	value V
	next  *lmNode[K, V]
	prev  *lmNode[K, V]
}

func newLinkedMap[K cmp.Ordered, V any]() *linkedMap[K, V] {
	m := &linkedMap[K, V]{
		items: make(map[K]*lmNode[K, V]),
	}
	m.head = &lmNode[K, V]{}
	m.tail = &lmNode[K, V]{}
	m.head.next = m.tail
	m.tail.prev = m.head
	return m
}

// =============================================================================
// Basic operations
// =============================================================================

func (m *linkedMap[K, V]) size() int {
	return m.len
}

func (m *linkedMap[K, V]) contains(key K) bool {
	_, exists := m.items[key]
	return exists
}

func (m *linkedMap[K, V]) get(key K) (V, bool) {
	if node, exists := m.items[key]; exists {
		return node.value, true
	}
	var zero V
	return zero, false
}

// put adds or updates a key-value pair, maintaining insertion order.
// If key exists, updates value but keeps position.
func (m *linkedMap[K, V]) put(key K, value V) {
	if existing, ok := m.items[key]; ok {
		existing.value = value
		return
	}

	newNode := &lmNode[K, V]{key: key, value: value}

	// Insert before tail
	predecessor := m.tail.prev
	newNode.next = m.tail
	newNode.prev = predecessor
	predecessor.next = newNode
	m.tail.prev = newNode

	m.items[key] = newNode
	m.len++
}

// putOrdered inserts in sorted position, searching backwards from end.
// O(1) for in-order arrivals (common case for stream offsets).
// O(n) for the worst case
func (m *linkedMap[K, V]) putOrdered(key K, value V) {
	if existing, ok := m.items[key]; ok {
		existing.value = value
		return
	}

	// Find insertion point (walk backwards)
	insertAfter := m.tail.prev
	for insertAfter != m.head && insertAfter.key > key {
		insertAfter = insertAfter.prev
	}

	newNode := &lmNode[K, V]{key: key, value: value}
	newNode.next = insertAfter.next
	newNode.prev = insertAfter
	insertAfter.next.prev = newNode
	insertAfter.next = newNode

	m.items[key] = newNode
	m.len++
}

func (m *linkedMap[K, V]) remove(key K) (V, bool) {
	node, ok := m.items[key]
	if !ok {
		var zero V
		return zero, false
	}

	// Unlink from list
	node.prev.next = node.next
	node.next.prev = node.prev

	delete(m.items, key)
	m.len--

	return node.value, true
}

// replace swaps oldKey for newKey, keeping the same list position.
// Fails if oldKey doesn't exist or newKey already exists (and differs from oldKey).
func (m *linkedMap[K, V]) replace(oldKey K, newKey K, value V) bool {
	oldNode, oldExists := m.items[oldKey]
	if !oldExists {
		return false
	}

	if oldKey == newKey {
		oldNode.value = value
		return true
	}

	if _, newExists := m.items[newKey]; newExists {
		return false
	}

	oldNode.key = newKey
	oldNode.value = value
	delete(m.items, oldKey)
	m.items[newKey] = oldNode

	return true
}

// =============================================================================
// Traversal - All O(1) when key exists
// =============================================================================

func (m *linkedMap[K, V]) first() (K, V, bool) {
	if m.head.next != m.tail {
		node := m.head.next
		return node.key, node.value, true
	}
	var zeroK K
	var zeroV V
	return zeroK, zeroV, false
}

func (m *linkedMap[K, V]) next(key K) (K, V, bool) {
	if node, exists := m.items[key]; exists && node.next != m.tail {
		return node.next.key, node.next.value, true
	}
	var zeroK K
	var zeroV V
	return zeroK, zeroV, false
}

func (m *linkedMap[K, V]) prev(key K) (K, V, bool) {
	node, exists := m.items[key]
	if !exists || node.prev == m.head {
		var zeroK K
		var zeroV V
		return zeroK, zeroV, false
	}
	return node.prev.key, node.prev.value, true
}

// iterator returns a Go 1.23+ iterator starting after startKey.
// Falls back to iterating from beginning if:
//   - startKey is nil
//   - startKey doesn't exist in the map
//   - startKey is the last element (no elements after it)
func (m *linkedMap[K, V]) iterator(startKey *K) iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		startNode := m.head.next
		if startKey != nil {
			if node, exists := m.items[*startKey]; exists && node.next != m.tail {
				startNode = node.next
			}
		}

		for node := startNode; node != m.tail; node = node.next {
			if !yield(node.key, node.value) {
				return
			}
		}
	}
}

// =============================================================================
// sharedLinkedMap - internally locked wrapper for cross-goroutine maps
// =============================================================================

// sharedLinkedMap guards a linkedMap with an RWMutex for maps accessed by
// both the event loop and user goroutines (conn.streams, listener.connMap).
// The composite operation that must be atomic lives here (getOrPut).
//
// Iteration is cursor-hopped: the lock is held only while advancing to the
// next entry, never while the caller's loop body runs — the body may safely
// call back into the map or block without self-deadlocking. Consequence:
// the iteration is not a snapshot; entries inserted behind the cursor are
// not visited, and if the current entry is removed mid-iteration the walk
// ends early (removals only happen on the event-loop goroutine, outside its
// own iterations, so this does not occur in practice).
type sharedLinkedMap[K cmp.Ordered, V any] struct {
	m  *linkedMap[K, V]
	mu sync.RWMutex
}

func newSharedLinkedMap[K cmp.Ordered, V any]() *sharedLinkedMap[K, V] {
	return &sharedLinkedMap[K, V]{m: newLinkedMap[K, V]()}
}

func (s *sharedLinkedMap[K, V]) size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.m.size()
}

func (s *sharedLinkedMap[K, V]) get(key K) (V, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.m.get(key)
}

// getOrPut returns the existing value for key, or inserts value and returns
// it. loaded reports whether the key was already present.
func (s *sharedLinkedMap[K, V]) getOrPut(key K, value V) (v V, loaded bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.m.get(key); ok {
		return existing, true
	}
	s.m.put(key, value)
	return value, false
}

func (s *sharedLinkedMap[K, V]) remove(key K) (V, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m.remove(key)
}

// iterator has the same start/fallback semantics as linkedMap.iterator, but
// hops the lock per entry (see type doc).
func (s *sharedLinkedMap[K, V]) iterator(startKey *K) iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		firstHop := true
		var cursor K
		hasCursor := startKey != nil
		if hasCursor {
			cursor = *startKey
		}

		for {
			s.mu.RLock()
			var k K
			var v V
			var ok bool
			if hasCursor {
				k, v, ok = s.m.next(cursor)
				if !ok && firstHop {
					// startKey missing or last element: fall back to the
					// beginning, matching linkedMap.iterator
					k, v, ok = s.m.first()
				}
			} else {
				k, v, ok = s.m.first()
			}
			s.mu.RUnlock()

			firstHop = false
			if !ok {
				return
			}
			if !yield(k, v) {
				return
			}
			cursor, hasCursor = k, true
		}
	}
}
