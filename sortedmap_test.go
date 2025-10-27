package qotp

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSortedMapBasicOperations(t *testing.T) {
	sm := NewSortedMap[int, string]()

	// Empty map
	assert.Equal(t, 0, sm.Size())
	minKey, minVal, ok := sm.Min()
	assert.False(t, ok)
	assert.Equal(t, 0, minKey)
	assert.Equal(t, "", minVal)

	// Put and Get
	sm.Put(1, "one")
	value, ok := sm.Get(1)
	assert.True(t, ok)
	assert.Equal(t, "one", value)

	// Update existing key
	sm.Put(1, "ONE")
	value, ok = sm.Get(1)
	assert.True(t, ok)
	assert.Equal(t, "ONE", value)
	assert.Equal(t, 1, sm.Size())

	// Non-existent key
	value, ok = sm.Get(999)
	assert.False(t, ok)
	assert.Equal(t, "", value)
}

func TestSortedMapContains(t *testing.T) {
	sm := NewSortedMap[int, string]()

	assert.False(t, sm.Contains(1))

	sm.Put(1, "one")
	sm.Put(2, "two")

	assert.True(t, sm.Contains(1))
	assert.True(t, sm.Contains(2))
	assert.False(t, sm.Contains(3))

	value, ok := sm.Remove(1)
	assert.True(t, ok)
	assert.Equal(t, "one", value)
	assert.False(t, sm.Contains(1))
	assert.True(t, sm.Contains(2))
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

func TestSortedMapNext(t *testing.T) {
	sm := NewSortedMap[int, string]()

	// Empty map
	nextKey, nextVal, ok := sm.Next(1)
	assert.False(t, ok)
	assert.Equal(t, 0, nextKey)
	assert.Equal(t, "", nextVal)

	// Single element
	sm.Put(1, "one")
	minKey, minVal, ok := sm.Min()
	assert.True(t, ok)
	assert.Equal(t, 1, minKey)
	assert.Equal(t, "one", minVal)

	nextKey, nextVal, ok = sm.Next(1)
	assert.False(t, ok)
	assert.Equal(t, 0, nextKey)
	assert.Equal(t, "", nextVal)

	// Multiple elements
	sm.Put(2, "two")
	sm.Put(3, "three")

	key, val, ok := sm.Min()
	assert.True(t, ok)
	assert.Equal(t, 1, key)
	assert.Equal(t, "one", val)

	key, val, ok = sm.Next(key)
	assert.True(t, ok)
	assert.Equal(t, 2, key)
	assert.Equal(t, "two", val)

	key, val, ok = sm.Next(key)
	assert.True(t, ok)
	assert.Equal(t, 3, key)
	assert.Equal(t, "three", val)

	key, val, ok = sm.Next(key)
	assert.False(t, ok)
	assert.Equal(t, 0, key)
	assert.Equal(t, "", val)
}

func TestSortedMapNextFromKey(t *testing.T) {
	sm := NewSortedMap[int, string]()

	values := []int{1, 3, 5, 7, 9}
	for _, v := range values {
		sm.Put(v, "value")
	}

	// Next from existing key
	nextKey, nextValue, ok := sm.Next(3)
	assert.True(t, ok)
	assert.Equal(t, 5, nextKey)
	assert.Equal(t, "value", nextValue)

	// Next from non-existing key
	nextKey, nextValue, ok = sm.Next(4)
	assert.True(t, ok)
	assert.Equal(t, 5, nextKey)
	assert.Equal(t, "value", nextValue)

	// Next from last key
	nextKey, nextValue, ok = sm.Next(9)
	assert.False(t, ok)
	assert.Equal(t, 0, nextKey)
	assert.Equal(t, "", nextValue)

	// Next from key larger than all
	nextKey, nextValue, ok = sm.Next(10)
	assert.False(t, ok)
	assert.Equal(t, 0, nextKey)
	assert.Equal(t, "", nextValue)
}

func TestSortedMapPrev(t *testing.T) {
	sm := NewSortedMap[int, string]()

	// Empty map
	prevKey, prevVal, ok := sm.Prev(5)
	assert.False(t, ok)
	assert.Equal(t, 0, prevKey)
	assert.Equal(t, "", prevVal)

	// Single element
	sm.Put(5, "five")

	prevKey, prevVal, ok = sm.Prev(5)
	assert.False(t, ok)
	assert.Equal(t, 0, prevKey)
	assert.Equal(t, "", prevVal)

	// Multiple elements
	sm.Put(1, "one")
	sm.Put(3, "three")
	sm.Put(7, "seven")
	sm.Put(9, "nine")

	key, val, ok := sm.Prev(9)
	assert.True(t, ok)
	assert.Equal(t, 7, key)
	assert.Equal(t, "seven", val)

	key, val, ok = sm.Prev(key)
	assert.True(t, ok)
	assert.Equal(t, 5, key)
	assert.Equal(t, "five", val)

	key, val, ok = sm.Prev(key)
	assert.True(t, ok)
	assert.Equal(t, 3, key)
	assert.Equal(t, "three", val)

	key, val, ok = sm.Prev(key)
	assert.True(t, ok)
	assert.Equal(t, 1, key)
	assert.Equal(t, "one", val)

	key, val, ok = sm.Prev(key)
	assert.False(t, ok)
	assert.Equal(t, 0, key)
	assert.Equal(t, "", val)
}

func TestSortedMapPrevFromKey(t *testing.T) {
	sm := NewSortedMap[int, string]()

	values := []int{1, 3, 5, 7, 9}
	for _, v := range values {
		sm.Put(v, "value")
	}

	// Prev from existing key
	prevKey, prevValue, ok := sm.Prev(7)
	assert.True(t, ok)
	assert.Equal(t, 5, prevKey)
	assert.Equal(t, "value", prevValue)

	// Prev from non-existing key
	prevKey, prevValue, ok = sm.Prev(6)
	assert.True(t, ok)
	assert.Equal(t, 5, prevKey)
	assert.Equal(t, "value", prevValue)

	// Prev from first key
	prevKey, prevValue, ok = sm.Prev(1)
	assert.False(t, ok)
	assert.Equal(t, 0, prevKey)
	assert.Equal(t, "", prevValue)

	// Prev from key smaller than all
	prevKey, prevValue, ok = sm.Prev(0)
	assert.False(t, ok)
	assert.Equal(t, 0, prevKey)
	assert.Equal(t, "", prevValue)

	// Prev from key larger than all
	prevKey, prevValue, ok = sm.Prev(15)
	assert.True(t, ok)
	assert.Equal(t, 9, prevKey)
	assert.Equal(t, "value", prevValue)
}

func TestSortedMapPrevNextSymmetry(t *testing.T) {
	sm := NewSortedMap[int, string]()

	values := []int{2, 4, 6, 8, 10}
	for _, v := range values {
		sm.Put(v, "value")
	}

	currentKey := 6

	// Go next
	nextKey, _, ok := sm.Next(currentKey)
	assert.True(t, ok)
	assert.Equal(t, 8, nextKey)

	// Go back with Prev
	prevKey, _, ok := sm.Prev(nextKey)
	assert.True(t, ok)
	assert.Equal(t, 6, prevKey)

	// Go prev
	prevKey, _, ok = sm.Prev(currentKey)
	assert.True(t, ok)
	assert.Equal(t, 4, prevKey)

	// Go forward with Next
	nextKey, _, ok = sm.Next(prevKey)
	assert.True(t, ok)
	assert.Equal(t, 6, nextKey)
}

func TestSortedMapPrevWithGaps(t *testing.T) {
	sm := NewSortedMap[int, string]()

	values := []int{1, 5, 10, 20, 50}
	for _, v := range values {
		sm.Put(v, "value")
	}

	prevKey, prevValue, ok := sm.Prev(15)
	assert.True(t, ok)
	assert.Equal(t, 10, prevKey)
	assert.Equal(t, "value", prevValue)

	prevKey, prevValue, ok = sm.Prev(7)
	assert.True(t, ok)
	assert.Equal(t, 5, prevKey)
	assert.Equal(t, "value", prevValue)

	prevKey, prevValue, ok = sm.Prev(3)
	assert.True(t, ok)
	assert.Equal(t, 1, prevKey)
	assert.Equal(t, "value", prevValue)

	prevKey, prevValue, ok = sm.Prev(51)
	assert.True(t, ok)
	assert.Equal(t, 50, prevKey)
	assert.Equal(t, "value", prevValue)

	prevKey, prevValue, ok = sm.Prev(1)
	assert.False(t, ok)
	assert.Equal(t, 0, prevKey)
	assert.Equal(t, "", prevValue)
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

func TestSortedMapUpdateValue(t *testing.T) {
	sm := NewSortedMap[int, string]()

	sm.Put(1, "original")
	value, ok := sm.Get(1)
	assert.True(t, ok)
	assert.Equal(t, "original", value)
	assert.Equal(t, 1, sm.Size())

	sm.Put(1, "updated")
	value, ok = sm.Get(1)
	assert.True(t, ok)
	assert.Equal(t, "updated", value)
	assert.Equal(t, 1, sm.Size())
}

func TestSortedMapRemoveNonExistent(t *testing.T) {
	sm := NewSortedMap[int, string]()

	removedVal, removed := sm.Remove(999)
	assert.False(t, removed)
	assert.Equal(t, "", removedVal)

	sm.Put(5, "five")
	assert.True(t, sm.Contains(5))
	removedVal, removed = sm.Remove(5)
	assert.True(t, removed)
	assert.Equal(t, "five", removedVal)
	assert.False(t, sm.Contains(5))
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

func TestSortedMapNextPrevAfterRemoval(t *testing.T) {
	sm := NewSortedMap[int, string]()
	
	sm.Put(1, "one")
	sm.Put(2, "two")
	sm.Put(3, "three")
	
	// Remove middle
	sm.Remove(2)
	
	// Next from 1 should skip to 3
	nextKey, nextVal, ok := sm.Next(1)
	assert.True(t, ok)
	assert.Equal(t, 3, nextKey)
	assert.Equal(t, "three", nextVal)
	
	// Prev from 3 should skip to 1
	prevKey, prevVal, ok := sm.Prev(3)
	assert.True(t, ok)
	assert.Equal(t, 1, prevKey)
	assert.Equal(t, "one", prevVal)
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

func TestSortedMapUpdateDoesntAffectOrder(t *testing.T) {
	sm := NewSortedMap[int, string]()
	
	sm.Put(1, "one")
	sm.Put(2, "two")
	sm.Put(3, "three")
	
	// Update middle element multiple times
	sm.Put(2, "TWO")
	sm.Put(2, "two-updated")
	sm.Put(2, "final")
	
	// Order should be preserved
	current, val, ok := sm.Min()
	assert.True(t, ok)
	assert.Equal(t, 1, current)
	
	current, val, ok = sm.Next(current)
	assert.True(t, ok)
	assert.Equal(t, 2, current)
	assert.Equal(t, "final", val) // Updated value
	
	current, _, ok = sm.Next(current)
	assert.True(t, ok)
	assert.Equal(t, 3, current)
}