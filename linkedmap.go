package qotp

import (
	"cmp"
	"iter"
	"sync"
)

// =============================================================================
// LinkedMap - Thread-safe hash map with O(1) operations and order preservation
//
// Two insertion modes:
// - Put(): Maintains insertion order (append to end)
// - PutOrdered(): Maintains sorted order (O(1) for in-order arrivals)
// =============================================================================

type linkedMap[K cmp.Ordered, V any] struct {
	items map[K]*lmNode[K, V]
	head  *lmNode[K, V] // Sentinel head node
	tail  *lmNode[K, V] // Sentinel tail node
	len  int
	mu    sync.RWMutex
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
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.len
}

func (m *linkedMap[K, V]) contains(key K) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.items[key]
	return exists
}

func (m *linkedMap[K, V]) get(key K) (V, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if node, exists := m.items[key]; exists {
		return node.value, true
	}
	var zero V
	return zero, false
}

// put adds or updates a key-value pair, maintaining insertion order.
// If key exists, updates value but keeps position.
func (m *linkedMap[K, V]) put(key K, value V) {
	m.mu.Lock()
	defer m.mu.Unlock()

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
	m.mu.Lock()
	defer m.mu.Unlock()

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
	m.mu.Lock()
	defer m.mu.Unlock()

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
	m.mu.Lock()
	defer m.mu.Unlock()

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
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.head.next != m.tail {
		node := m.head.next
		return node.key, node.value, true
	}
	var zeroK K
	var zeroV V
	return zeroK, zeroV, false
}

func (m *linkedMap[K, V]) next(key K) (K, V, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if node, exists := m.items[key]; exists && node.next != m.tail {
		return node.next.key, node.next.value, true
	}
	var zeroK K
	var zeroV V
	return zeroK, zeroV, false
}

func (m *linkedMap[K, V]) prev(key K) (K, V, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

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
		m.mu.RLock()
		defer m.mu.RUnlock()

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