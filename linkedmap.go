package qotp

import (
	"cmp"
	"iter"
	"sync"
)

// =============================================================================
// linkedMap - hash map that also keeps an order: insertion order with put,
// sorted order with putOrdered. Not goroutine-safe; the owner's lock covers
// it together with the owner's other state. sharedLinkedMap below is for
// maps shared across goroutines.
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

func (m *linkedMap[K, V]) get(key K) (V, bool) {
	if node, exists := m.items[key]; exists {
		return node.value, true
	}
	var zero V
	return zero, false
}

// put appends; an existing key keeps its position
func (m *linkedMap[K, V]) put(key K, value V) {
	if existing, ok := m.items[key]; ok {
		existing.value = value
		return
	}

	newNode := &lmNode[K, V]{key: key, value: value}
	predecessor := m.tail.prev
	newNode.next = m.tail
	newNode.prev = predecessor
	predecessor.next = newNode
	m.tail.prev = newNode

	m.items[key] = newNode
	m.len++
}

// putOrdered inserts in sorted position, searching backwards from the end:
// O(1) for in-order arrivals
func (m *linkedMap[K, V]) putOrdered(key K, value V) {
	if existing, ok := m.items[key]; ok {
		existing.value = value
		return
	}

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

	node.prev.next = node.next
	node.next.prev = node.prev

	delete(m.items, key)
	m.len--

	return node.value, true
}

// replace renames a key in place. Fails if oldKey is missing or newKey taken.
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
// Traversal
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

// =============================================================================
// sharedLinkedMap - locked wrapper for maps shared across goroutines
//
// Iteration holds the lock only while advancing, never during the caller's
// loop body, so the body may call back into the map. It is therefore not a
// snapshot: entries inserted behind the cursor are not visited, and removing
// the current entry ends the walk early.
// =============================================================================

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

// getOrPut returns the existing value, or inserts value; loaded reports which
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

// iterator starts after startKey, or from the beginning when startKey is
// nil, missing, or the last element
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
