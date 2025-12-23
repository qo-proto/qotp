package qotp

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSortedMapBasicOperations(t *testing.T) {
	sm := NewSortedMap[int, string]()

	// Empty state
	assert.Equal(t, 0, sm.Size())
	_, _, ok := sm.Min()
	assert.False(t, ok)
	assert.False(t, sm.Contains(1))

	// Put and Get
	sm.Put(1, "one")
	v, ok := sm.Get(1)
	assert.True(t, ok)
	assert.Equal(t, "one", v)
	assert.True(t, sm.Contains(1))

	// Update existing
	sm.Put(1, "ONE")
	v, _ = sm.Get(1)
	assert.Equal(t, "ONE", v)
	assert.Equal(t, 1, sm.Size()) // Size unchanged

	// Non-existent
	_, ok = sm.Get(999)
	assert.False(t, ok)
	assert.False(t, sm.Contains(999))
}

func TestSortedMapOrderedTraversal(t *testing.T) {
	sm := NewSortedMap[int, string]()

	values := []struct {
		key   int
		value string
	}{
		{5, "five"},
		{3, "three"},
		{7, "seven"},
		{1, "one"},
		{9, "nine"},
		{4, "four"},
		{6, "six"},
	}

	for _, v := range values {
		sm.Put(v.key, v.value)
	}

	expected := []int{1, 3, 4, 5, 6, 7, 9}

	currentKey, currentVal, ok := sm.Min()
	assert.True(t, ok)
	assert.Equal(t, 1, currentKey)
	assert.Equal(t, "one", currentVal)

	for i, exp := range expected {
		assert.Equal(t, exp, currentKey)
		if i < len(expected)-1 {
			currentKey, _, ok = sm.Next(currentKey)
			assert.True(t, ok)
		}
	}

	nextKey, nextVal, ok := sm.Next(currentKey)
	assert.False(t, ok)
	assert.Equal(t, 0, nextKey)
	assert.Equal(t, "", nextVal)
}

func TestSortedMapRemove(t *testing.T) {
	sm := NewSortedMap[int, string]()

	// Remove from empty
	value, ok := sm.Remove(1)
	assert.False(t, ok)
	assert.Equal(t, "", value)

	values := []int{8, 4, 12, 2, 6, 10, 14, 1, 3, 5, 7, 9, 11, 13, 15}
	for _, v := range values {
		sm.Put(v, "value")
	}

	value, ok = sm.Remove(15)
	assert.True(t, ok)
	assert.Equal(t, "value", value)
	_, exists := sm.Get(15)
	assert.False(t, exists)

	value, ok = sm.Remove(14)
	assert.True(t, ok)
	assert.Equal(t, "value", value)

	assert.True(t, sm.Contains(13))

	value, ok = sm.Remove(8)
	assert.True(t, ok)
	assert.Equal(t, "value", value)

	assert.True(t, sm.Contains(1))
	assert.True(t, sm.Contains(13))
	assert.False(t, sm.Contains(8))
	assert.False(t, sm.Contains(14))
	assert.False(t, sm.Contains(15))
}

func TestSortedMapMin(t *testing.T) {
	sm := NewSortedMap[int, string]()

	minKey, minVal, ok := sm.Min()
	assert.False(t, ok)
	assert.Equal(t, 0, minKey)
	assert.Equal(t, "", minVal)

	values := map[int]string{
		5: "five",
		3: "three",
		7: "seven",
		1: "one",
		9: "nine",
	}
	for k, v := range values {
		sm.Put(k, v)
	}

	minKey, minVal, ok = sm.Min()
	assert.True(t, ok)
	assert.Equal(t, 1, minKey)
	assert.Equal(t, "one", minVal)

	removedVal, removed := sm.Remove(1)
	assert.True(t, removed)
	assert.Equal(t, "one", removedVal)

	minKey, minVal, ok = sm.Min()
	assert.True(t, ok)
	assert.Equal(t, 3, minKey)
	assert.Equal(t, "three", minVal)
}

func TestSortedMapPrev(t *testing.T) {
	sm := NewSortedMap[int, string]()

	// Empty map
	_, _, ok := sm.Prev(5)
	assert.False(t, ok)

	// Setup: 1, 5, 10, 20, 50
	for _, v := range []int{1, 5, 10, 20, 50} {
		sm.Put(v, "val")
	}

	// Prev from existing key
	k, _, ok := sm.Prev(20)
	assert.True(t, ok)
	assert.Equal(t, 10, k)

	// Prev from non-existing key (finds previous)
	k, _, ok = sm.Prev(15)
	assert.True(t, ok)
	assert.Equal(t, 10, k)

	// Prev from first key
	_, _, ok = sm.Prev(1)
	assert.False(t, ok)

	// Prev from key smaller than all
	_, _, ok = sm.Prev(0)
	assert.False(t, ok)

	// Prev from key larger than all
	k, _, ok = sm.Prev(100)
	assert.True(t, ok)
	assert.Equal(t, 50, k)
}

func TestSortedMapConcurrent(t *testing.T) {
	sm := NewSortedMap[int, string]()
	var wg sync.WaitGroup
	numGoroutines := 10
	numOperations := 100

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				val := base*numOperations + j
				sm.Put(val, "value")
			}
		}(i)
	}

	// Concurrent reads and removes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				if j%2 == 0 {
					sm.Get(j)
				} else {
					sm.Remove(j)
				}
			}
		}()
	}

	wg.Wait()
}

func TestSortedMapRemoveAllThenAdd(t *testing.T) {
	sm := NewSortedMap[int, string]()
	
	sm.Put(1, "one")
	sm.Put(2, "two")
	sm.Put(3, "three")
	
	sm.Remove(1)
	sm.Remove(2)
	sm.Remove(3)
	
	assert.Equal(t, 0, sm.Size())
	
	// Add again - level should reset properly
	sm.Put(5, "five")
	sm.Put(10, "ten")
	
	minKey, _, ok := sm.Min()
	assert.True(t, ok)
	assert.Equal(t, 5, minKey)
}

func TestSortedMapLevelGrowth(t *testing.T) {
	sm := NewSortedMap[int, string]()
	
	// Add 16 elements (4^2) - should grow to level 3
	for i := 0; i < 16; i++ {
		sm.Put(i, "value")
	}
	
	// Remove all - level should decrease
	for i := 0; i < 16; i++ {
		sm.Remove(i)
	}
	
	// Verify map still works
	sm.Put(100, "hundred")
	val, ok := sm.Get(100)
	assert.True(t, ok)
	assert.Equal(t, "hundred", val)
}

func TestSortedMapNext(t *testing.T) {
	sm := NewSortedMap[int, string]()

	// Empty map
	_, _, ok := sm.Next(1)
	assert.False(t, ok)

	// Setup: 1, 3, 5, 7, 9
	for _, v := range []int{1, 3, 5, 7, 9} {
		sm.Put(v, "val")
	}

	// Next from existing key
	k, _, ok := sm.Next(3)
	assert.True(t, ok)
	assert.Equal(t, 5, k)

	// Next from non-existing key (finds next greater)
	k, _, ok = sm.Next(4)
	assert.True(t, ok)
	assert.Equal(t, 5, k)

	// Next from last key
	_, _, ok = sm.Next(9)
	assert.False(t, ok)

	// Next from key larger than all
	_, _, ok = sm.Next(10)
	assert.False(t, ok)
}

func TestSortedMapSkipListIntegrity(t *testing.T) {
	sm := NewSortedMap[int, string]()
	
	// Add in random order
	values := []int{50, 25, 75, 10, 30, 60, 80, 5, 15, 35, 55, 65, 85}
	for _, v := range values {
		sm.Put(v, "value")
	}
	
	// Remove some
	sm.Remove(25)
	sm.Remove(60)
	sm.Remove(10)
	
	// Verify complete forward traversal
	expected := []int{5, 15, 30, 35, 50, 55, 65, 75, 80, 85}
	current, _, ok := sm.Min()
	assert.True(t, ok)
	
	for _, exp := range expected {
		assert.Equal(t, exp, current)
		if exp != expected[len(expected)-1] {
			current, _, ok = sm.Next(current)
			assert.True(t, ok)
		}
	}
	
	// Verify complete backward traversal
	for i := len(expected) - 1; i >= 0; i-- {
		assert.Equal(t, expected[i], current)
		if i > 0 {
			current, _, ok = sm.Prev(current)
			assert.True(t, ok)
		}
	}
}
