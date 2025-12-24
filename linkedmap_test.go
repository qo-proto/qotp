package qotp

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Basic LinkedMap Tests (insertion order)
// =============================================================================

func TestLinkedMapNewLinkedMap(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	assert.NotNil(t, lm)
	assert.NotNil(t, lm.items)
	assert.NotNil(t, lm.head)
	assert.NotNil(t, lm.tail)
	assert.Equal(t, 0, lm.size)
	assert.Equal(t, lm.tail, lm.head.next)
	assert.Equal(t, lm.head, lm.tail.prev)
}

func TestLinkedMapPut(t *testing.T) {
	lm := NewLinkedMap[string, int]()

	lm.Put("a", 1)
	lm.Put("b", 2)
	lm.Put("c", 3)
	assert.Equal(t, 3, lm.Size())
	v, ok := lm.Get("a")
	assert.True(t, ok)
	assert.Equal(t, 1, v)
	v, ok = lm.Get("b")
	assert.True(t, ok)
	assert.Equal(t, 2, v)

	// Update existing key - size unchanged, order preserved
	lm.Put("b", 200)
	assert.Equal(t, 3, lm.Size())
	v, ok = lm.Get("b")
	assert.True(t, ok)
	assert.Equal(t, 200, v)

	// Verify order: a -> b -> c
	k, v, ok := lm.First()
	assert.True(t, ok)
	assert.Equal(t, "a", k)
	assert.Equal(t, 1, v)

	k, v, ok = lm.Next("a")
	assert.True(t, ok)
	assert.Equal(t, "b", k)
	assert.Equal(t, 200, v)
}

func TestLinkedMapGet(t *testing.T) {
	lm := NewLinkedMap[string, int]()

	// Non-existent returns zero value and false
	v, ok := lm.Get("missing")
	assert.False(t, ok)
	assert.Equal(t, 0, v)

	// Existing key
	lm.Put("key", 42)
	v, ok = lm.Get("key")
	assert.True(t, ok)
	assert.Equal(t, 42, v)

	// Zero value is distinguishable via ok
	lm.Put("zero", 0)
	v, ok = lm.Get("zero")
	assert.True(t, ok)
	assert.Equal(t, 0, v)
	assert.True(t, lm.Contains("zero"))
}

func TestLinkedMapContains(t *testing.T) {
	lm := NewLinkedMap[string, int]()

	assert.False(t, lm.Contains("any"))

	lm.Put("key", 42)
	lm.Put("zero", 0)

	assert.True(t, lm.Contains("key"))
	assert.True(t, lm.Contains("zero"))
	assert.False(t, lm.Contains("missing"))

	lm.Remove("key")
	assert.False(t, lm.Contains("key"))
}

func TestLinkedMapRemove(t *testing.T) {
	lm := NewLinkedMap[string, int]()

	// Empty map
	_, ok := lm.Remove("any")
	assert.False(t, ok)

	lm.Put("a", 1)
	lm.Put("b", 2)
	lm.Put("c", 3)

	// Remove middle element
	v, ok := lm.Remove("b")
	assert.True(t, ok)
	assert.Equal(t, 2, v)
	assert.Equal(t, 2, lm.Size())

	// Links updated: a -> c
	k, _, ok := lm.Next("a")
	assert.True(t, ok)
	assert.Equal(t, "c", k)

	// Remove first
	lm.Remove("a")
	k, _, ok = lm.First()
	assert.True(t, ok)
	assert.Equal(t, "c", k)

	// Remove non-existent
	_, ok = lm.Remove("missing")
	assert.False(t, ok)
}

func TestLinkedMapFirst(t *testing.T) {
	lm := NewLinkedMap[string, int]()

	// Empty
	_, _, ok := lm.First()
	assert.False(t, ok)

	// Single element
	lm.Put("only", 42)
	k, v, ok := lm.First()
	assert.True(t, ok)
	assert.Equal(t, "only", k)
	assert.Equal(t, 42, v)

	// Multiple - returns first inserted
	lm.Put("second", 2)
	k, _, _ = lm.First()
	assert.Equal(t, "only", k)
}

func TestLinkedMapNext(t *testing.T) {
	lm := NewLinkedMap[string, int]()

	lm.Put("a", 1)
	lm.Put("b", 2)
	lm.Put("c", 3)

	// Traverse forward
	k, v, ok := lm.Next("a")
	assert.True(t, ok)
	assert.Equal(t, "b", k)
	assert.Equal(t, 2, v)

	k, v, ok = lm.Next("b")
	assert.True(t, ok)
	assert.Equal(t, "c", k)

	// Last element has no next
	_, _, ok = lm.Next("c")
	assert.False(t, ok)

	// Non-existent key
	_, _, ok = lm.Next("missing")
	assert.False(t, ok)
}

func TestLinkedMapNextEmptyMap(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	key, value, ok := lm.Next("any")
	assert.False(t, ok)
	assert.Equal(t, "", key)
	assert.Equal(t, 0, value)
}

func TestLinkedMapNextSingleElement(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	only := "only"
	lm.Put(only, 42)

	key, value, ok := lm.Next(only)
	assert.False(t, ok)
	assert.Equal(t, "", key)
	assert.Equal(t, 0, value)
}

func TestLinkedMapPrev(t *testing.T) {
	lm := NewLinkedMap[string, int]()

	lm.Put("a", 1)
	lm.Put("b", 2)
	lm.Put("c", 3)

	k, v, ok := lm.Prev("c")
	assert.True(t, ok)
	assert.Equal(t, "b", k)
	assert.Equal(t, 2, v)

	// First element has no previous
	_, _, ok = lm.Prev("a")
	assert.False(t, ok)
}

func TestLinkedMapReplace(t *testing.T) {
	lm := NewLinkedMap[string, int]()

	lm.Put("a", 1)
	lm.Put("b", 2)
	lm.Put("c", 3)

	// Replace middle element
	ok := lm.Replace("b", "B", 200)
	assert.True(t, ok)
	assert.False(t, lm.Contains("b"))
	v, _ := lm.Get("B")
	assert.Equal(t, 200, v)

	// Order preserved: a -> B -> c
	k, _, _ := lm.Next("a")
	assert.Equal(t, "B", k)
	k, _, _ = lm.Next("B")
	assert.Equal(t, "c", k)

	// Replace with same key (just update value)
	ok = lm.Replace("a", "a", 100)
	assert.True(t, ok)
	v, _ = lm.Get("a")
	assert.Equal(t, 100, v)

	// Replace non-existent fails
	ok = lm.Replace("missing", "new", 0)
	assert.False(t, ok)

	// Replace to existing key fails
	ok = lm.Replace("a", "c", 0)
	assert.False(t, ok)
}

func TestLinkedMapIteratorEmptyMap(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	count := 0
	for range lm.Iterator(nil) {
		count++
	}
	assert.Equal(t, 0, count)
}

func TestLinkedMapIteratorSingleElement(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	single := "single"
	lm.Put(single, 42)

	count := 0
	for key, value := range lm.Iterator(nil) {
		assert.Equal(t, single, key)
		assert.Equal(t, 42, value)
		count++
	}
	assert.Equal(t, 1, count)
}

func TestLinkedMapIteratorMultipleElements(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	first := "first"
	second := "second"
	third := "third"

	lm.Put(first, 1)
	lm.Put(second, 2)
	lm.Put(third, 3)

	expected := []struct {
		key   string
		value int
	}{
		{first, 1},
		{second, 2},
		{third, 3},
	}

	i := 0
	for key, value := range lm.Iterator(nil) {
		assert.Equal(t, expected[i].key, key)
		assert.Equal(t, expected[i].value, value)
		i++
	}
	assert.Equal(t, 3, i)
}

func TestLinkedMapIteratorWithStartKey(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	first := "first"
	second := "second"
	third := "third"

	lm.Put(first, 1)
	lm.Put(second, 2)
	lm.Put(third, 3)

	// Start from second element
	expected := []struct {
		key   string
		value int
	}{
		{third, 3}, // Should start from the element after "second"
	}

	i := 0
	for key, value := range lm.Iterator(&second) {
		assert.Equal(t, expected[i].key, key)
		assert.Equal(t, expected[i].value, value)
		i++
	}
	assert.Equal(t, 1, i)
}

func TestLinkedMapIteratorWithNonExistentStartKey(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	first := "first"
	second := "second"

	lm.Put(first, 1)
	lm.Put(second, 2)

	nonExistent := "nonexistent"
	count := 0
	for range lm.Iterator(&nonExistent) {
		count++
	}
	// Should iterate from beginning when start key doesn't exist
	assert.Equal(t, 2, count)
}

func TestLinkedMapIteratorPreservesInsertionOrder(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	// Add elements in specific order
	z := "z"
	a := "a"
	m := "m"

	lm.Put(z, 26)
	lm.Put(a, 1)
	lm.Put(m, 13)

	// Should iterate in insertion order, not alphabetical
	expected := []struct {
		key   string
		value int
	}{
		{z, 26},
		{a, 1},
		{m, 13},
	}

	i := 0
	for key, value := range lm.Iterator(nil) {
		assert.Equal(t, expected[i].key, key)
		assert.Equal(t, expected[i].value, value)
		i++
	}
	assert.Equal(t, 3, i)
}

func TestLinkedMapIteratorAfterUpdates(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	a := "a"
	b := "b"
	c := "c"

	lm.Put(a, 1)
	lm.Put(b, 2)
	lm.Put(c, 3)

	// Update middle element (should not change order)
	lm.Put(b, 200)

	expected := []struct {
		key   string
		value int
	}{
		{a, 1},
		{b, 200}, // Updated value
		{c, 3},
	}

	i := 0
	for key, value := range lm.Iterator(nil) {
		assert.Equal(t, expected[i].key, key)
		assert.Equal(t, expected[i].value, value)
		i++
	}
	assert.Equal(t, 3, i)
}

func TestLinkedMapIteratorAfterRemovals(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	a := "a"
	b := "b"
	c := "c"
	d := "d"

	lm.Put(a, 1)
	lm.Put(b, 2)
	lm.Put(c, 3)
	lm.Put(d, 4)

	// Remove middle element
	lm.Remove(b)

	expected := []struct {
		key   string
		value int
	}{
		{a, 1},
		{c, 3},
		{d, 4},
	}

	i := 0
	for key, value := range lm.Iterator(nil) {
		assert.Equal(t, expected[i].key, key)
		assert.Equal(t, expected[i].value, value)
		i++
	}
	assert.Equal(t, 3, i)
}

func TestLinkedMapIteratorAfterReplacement(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	a := "a"
	b := "b"
	c := "c"
	d := "d"

	lm.Put(a, 1)
	lm.Put(b, 2)
	lm.Put(c, 3)
	lm.Put(d, 4)

	// Replace 'a' with 'B'
	lm.Replace(a, "B", 20)

	// Order is now: B -> b -> c -> d
	key, value, ok := lm.First()
	assert.True(t, ok)
	assert.Equal(t, "B", key)
	assert.Equal(t, 20, value)

	key, value, ok = lm.Next("B")
	assert.True(t, ok)
	assert.Equal(t, b, key)
	assert.Equal(t, 2, value)

	key, value, ok = lm.Next(b)
	assert.True(t, ok)
	assert.Equal(t, c, key)
	assert.Equal(t, 3, value)
}

func TestLinkedMapTraversalAfterOperations(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	// Build a sequence
	keys := make([]string, 5)
	for i := 0; i < 5; i++ {
		key := string(rune('a' + i))
		keys[i] = key
		lm.Put(key, i)
	}

	// Remove some elements
	_, ok := lm.Remove(keys[1]) // Remove second (b)
	assert.True(t, ok)
	_, ok = lm.Remove(keys[3]) // Remove fourth (d)
	assert.True(t, ok)

	// Expected order: a(0), c(2), e(4)
	expected := []struct {
		key   string
		value int
	}{
		{keys[0], 0}, // a
		{keys[2], 2}, // c
		{keys[4], 4}, // e
	}

	// Traverse and verify
	key, value, ok := lm.First()
	assert.True(t, ok)
	for i, exp := range expected {
		assert.Equal(t, exp.key, key, "Position %d", i)
		assert.Equal(t, exp.value, value, "Position %d", i)

		if i < len(expected)-1 {
			key, value, ok = lm.Next(key)
			assert.True(t, ok)
		}
	}
}

func TestLinkedMapWithStringKeys(t *testing.T) {
	strMap := NewLinkedMap[string, string]()

	hello := "hello"
	foo := "foo"

	strMap.Put(hello, "world")
	strMap.Put(foo, "bar")

	v, ok := strMap.Get(hello)
	assert.True(t, ok)
	assert.Equal(t, "world", v)
	v, ok = strMap.Get(foo)
	assert.True(t, ok)
	assert.Equal(t, "bar", v)
	assert.True(t, strMap.Contains(hello))
	assert.Equal(t, 2, strMap.Size())
}

func TestLinkedMapSingleElementOperations(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	single := "single"
	replaced := "replaced"

	lm.Put(single, 42)

	// Test all operations
	assert.Equal(t, 1, lm.Size())
	assert.True(t, lm.Contains(single))
	v, ok := lm.Get(single)
	assert.True(t, ok)
	assert.Equal(t, 42, v)

	key, value, ok := lm.First()
	assert.True(t, ok)
	assert.Equal(t, single, key)
	assert.Equal(t, 42, value)

	nextKey, nextValue, ok := lm.Next(single)
	assert.False(t, ok)
	assert.Equal(t, "", nextKey)
	assert.Equal(t, 0, nextValue)

	// Replace
	assert.True(t, lm.Replace(single, replaced, 100))
	assert.False(t, lm.Contains(single))
	assert.True(t, lm.Contains(replaced))

	// Remove
	removedValue, ok := lm.Remove(replaced)
	assert.True(t, ok)
	assert.Equal(t, 100, removedValue)
	assert.Equal(t, 0, lm.Size())
}

func TestLinkedMapBidirectionalTraversal(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	a := "a"
	b := "b"
	c := "c"
	d := "d"

	lm.Put(a, 1)
	lm.Put(b, 2)
	lm.Put(c, 3)
	lm.Put(d, 4)

	// Forward traversal
	key, value, ok := lm.First()
	assert.True(t, ok)
	assert.Equal(t, a, key)
	assert.Equal(t, 1, value)

	key, value, ok = lm.Next(a)
	assert.True(t, ok)
	assert.Equal(t, b, key)
	assert.Equal(t, 2, value)

	key, value, ok = lm.Next(b)
	assert.True(t, ok)
	assert.Equal(t, c, key)
	assert.Equal(t, 3, value)

	// Backward traversal from current position
	key, value, ok = lm.Prev(c)
	assert.True(t, ok)
	assert.Equal(t, b, key)
	assert.Equal(t, 2, value)

	key, value, ok = lm.Prev(b)
	assert.True(t, ok)
	assert.Equal(t, a, key)
	assert.Equal(t, 1, value)
}

func TestLinkedMapPreviousAfterOperations(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	a := "a"
	b := "b"
	c := "c"
	d := "d"

	lm.Put(a, 1)
	lm.Put(b, 2)
	lm.Put(c, 3)
	lm.Put(d, 4)

	// Remove middle element
	_, ok := lm.Remove(b)
	assert.True(t, ok)

	// Check that previous relationships are updated correctly
	key, value, ok := lm.Prev(c)
	assert.True(t, ok)
	assert.Equal(t, a, key)
	assert.Equal(t, 1, value)
}

func TestLinkedMapPreviousAfterReplace(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	first := "first"
	second := "second"
	third := "third"
	SECOND := "SECOND"

	lm.Put(first, 1)
	lm.Put(second, 2)
	lm.Put(third, 3)

	// Replace middle element
	success := lm.Replace(second, SECOND, 200)
	assert.True(t, success)

	// Check previous relationships are maintained
	key, value, ok := lm.Prev(third)
	assert.True(t, ok)
	assert.Equal(t, SECOND, key)
	assert.Equal(t, 200, value)

	key, value, ok = lm.Prev(SECOND)
	assert.True(t, ok)
	assert.Equal(t, first, key)
	assert.Equal(t, 1, value)
}

func TestLinkedMapConcurrentReadOperations(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	// Populate map
	keys := make([]string, 100)
	for i := 0; i < 100; i++ {
		key := string(rune('a'+i%26)) + strconv.Itoa(i)
		keys[i] = key
		lm.Put(key, i)
	}

	var wg sync.WaitGroup
	numGoroutines := 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Perform various read operations
			for j := 0; j < 50; j++ {
				key := keys[j]

				_, _ = lm.Get(key)
				_ = lm.Contains(key)
				_ = lm.Size()

				if lm.Contains(key) {
					_, _, _ = lm.Next(key)
					_, _, _ = lm.Prev(key)
				}

				_, _, _ = lm.First()
			}
		}(i)
	}

	wg.Wait()

	// Verify map integrity
	assert.Equal(t, 100, lm.Size())
}

func TestLinkedMapConcurrentWriteOperations(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	var wg sync.WaitGroup
	numGoroutines := 5

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Each goroutine works with its own key range to avoid conflicts
			baseKey := string(rune('a' + id))
			for j := 0; j < 20; j++ {
				key := baseKey + strconv.Itoa(j)
				lm.Put(key, id*1000+j)
			}
		}(i)
	}

	wg.Wait()

	// Verify all elements were added
	assert.Equal(t, 100, lm.Size())
}

func TestLinkedMapConcurrentMixedOperations(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	// Pre-populate with some data
	keys := make([]string, 50)
	for i := 0; i < 50; i++ {
		key := string(rune('a'+i%26)) + strconv.Itoa(i)
		keys[i] = key
		lm.Put(key, i)
	}

	var wg sync.WaitGroup

	// Reader goroutines
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				key := keys[j%50]
				_, _ = lm.Get(key)
				_ = lm.Contains(key)
				if j%10 == 0 {
					time.Sleep(time.Microsecond)
				}
			}
		}()
	}

	// Writer goroutines
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			baseOffset := (id + 1) * 1000
			for j := 0; j < 30; j++ {
				key := "writer" + strconv.Itoa(id) + "_" + strconv.Itoa(j)
				lm.Put(key, baseOffset+j)
				if j%5 == 0 {
					time.Sleep(time.Microsecond)
				}
			}
		}(i)
	}

	wg.Wait()

	// Verify final state
	assert.True(t, lm.Size() >= 50)  // At least original elements
	assert.True(t, lm.Size() <= 110) // Original + new elements
}

func TestLinkedMapNestedIteratorBasic(t *testing.T) {
	// Create outer map with inner maps
	outerMap := NewLinkedMap[string, *LinkedMap[string, int]]()

	// Create inner maps
	innerMap1 := NewLinkedMap[string, int]()
	innerMap1.Put("item1", 1)
	innerMap1.Put("item2", 2)

	innerMap2 := NewLinkedMap[string, int]()
	innerMap2.Put("item3", 3)
	innerMap2.Put("item4", 4)

	// Add to outer map
	outerMap.Put("group1", innerMap1)
	outerMap.Put("group2", innerMap2)

	// Test nested iterator
	expected := []struct {
		outer *LinkedMap[string, int]
		inner int
	}{
		{innerMap1, 1},
		{innerMap1, 2},
		{innerMap2, 3},
		{innerMap2, 4},
	}

	i := 0
	for outerVal, innerVal := range NestedIterator(outerMap, func(v *LinkedMap[string, int]) *LinkedMap[string, int] { return v }, nil, nil) {
		assert.Equal(t, expected[i].outer, outerVal)
		assert.Equal(t, expected[i].inner, innerVal)
		i++
	}
	assert.Equal(t, 4, i)
}

func TestLinkedMapNestedIteratorWithStartKeys(t *testing.T) {
	// Create nested structure
	outerMap := NewLinkedMap[string, *LinkedMap[string, int]]()

	innerMap1 := NewLinkedMap[string, int]()
	innerMap1.Put("a", 1)
	innerMap1.Put("b", 2)

	innerMap2 := NewLinkedMap[string, int]()
	innerMap2.Put("c", 3)
	innerMap2.Put("d", 4)

	outerMap.Put("first", innerMap1)
	outerMap.Put("second", innerMap2)

	// Test with start keys
	startOuter := "first"
	startInner := "b"

	// Should start from "second" group (next after "first") and all its items
	expected := []struct {
		outer *LinkedMap[string, int]
		inner int
	}{
		{innerMap2, 3},
		{innerMap2, 4},
	}

	i := 0
	for outerVal, innerVal := range NestedIterator(outerMap, func(v *LinkedMap[string, int]) *LinkedMap[string, int] { return v }, &startOuter, &startInner) {
		assert.Equal(t, expected[i].outer, outerVal)
		assert.Equal(t, expected[i].inner, innerVal)
		i++
	}
	assert.Equal(t, 2, i)
}

// =============================================================================
// PutOrdered Tests (sorted order - replaces SortedMap)
// =============================================================================

func TestLinkedMapPutOrderedBasicOperations(t *testing.T) {
	sm := NewLinkedMap[int, string]()

	// Empty state
	assert.Equal(t, 0, sm.Size())
	_, _, ok := sm.Min()
	assert.False(t, ok)
	assert.False(t, sm.Contains(1))

	// PutOrdered and Get
	sm.PutOrdered(1, "one")
	v, ok := sm.Get(1)
	assert.True(t, ok)
	assert.Equal(t, "one", v)
	assert.True(t, sm.Contains(1))

	// Update existing
	sm.PutOrdered(1, "ONE")
	v, _ = sm.Get(1)
	assert.Equal(t, "ONE", v)
	assert.Equal(t, 1, sm.Size()) // Size unchanged

	// Non-existent
	_, ok = sm.Get(999)
	assert.False(t, ok)
	assert.False(t, sm.Contains(999))
}

func TestLinkedMapPutOrderedTraversal(t *testing.T) {
	sm := NewLinkedMap[int, string]()

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
		sm.PutOrdered(v.key, v.value)
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

func TestLinkedMapPutOrderedRemove(t *testing.T) {
	sm := NewLinkedMap[int, string]()

	// Remove from empty
	value, ok := sm.Remove(1)
	assert.False(t, ok)
	assert.Equal(t, "", value)

	values := []int{8, 4, 12, 2, 6, 10, 14, 1, 3, 5, 7, 9, 11, 13, 15}
	for _, v := range values {
		sm.PutOrdered(v, "value")
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

func TestLinkedMapPutOrderedMin(t *testing.T) {
	sm := NewLinkedMap[int, string]()

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
		sm.PutOrdered(k, v)
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

func TestLinkedMapPutOrderedPrev(t *testing.T) {
	sm := NewLinkedMap[int, string]()

	// Empty map
	_, _, ok := sm.Prev(5)
	assert.False(t, ok)

	// Setup: 1, 5, 10, 20, 50
	for _, v := range []int{1, 5, 10, 20, 50} {
		sm.PutOrdered(v, "val")
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

func TestLinkedMapPutOrderedConcurrent(t *testing.T) {
	sm := NewLinkedMap[int, string]()
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
				sm.PutOrdered(val, "value")
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

func TestLinkedMapPutOrderedRemoveAllThenAdd(t *testing.T) {
	sm := NewLinkedMap[int, string]()

	sm.PutOrdered(1, "one")
	sm.PutOrdered(2, "two")
	sm.PutOrdered(3, "three")

	sm.Remove(1)
	sm.Remove(2)
	sm.Remove(3)

	assert.Equal(t, 0, sm.Size())

	// Add again
	sm.PutOrdered(5, "five")
	sm.PutOrdered(10, "ten")

	minKey, _, ok := sm.Min()
	assert.True(t, ok)
	assert.Equal(t, 5, minKey)
}

func TestLinkedMapPutOrderedNext(t *testing.T) {
	sm := NewLinkedMap[int, string]()

	// Empty map
	_, _, ok := sm.Next(1)
	assert.False(t, ok)

	// Setup: 1, 3, 5, 7, 9
	for _, v := range []int{1, 3, 5, 7, 9} {
		sm.PutOrdered(v, "val")
	}

	// Next from existing key
	k, _, ok := sm.Next(3)
	assert.True(t, ok)
	assert.Equal(t, 5, k)

	// Next from last key
	_, _, ok = sm.Next(9)
	assert.False(t, ok)

	// Next from non-existent key returns nothing (key doesn't exist)
	_, _, ok = sm.Next(4)
	assert.False(t, ok)
}

func TestLinkedMapPutOrderedIntegrity(t *testing.T) {
	sm := NewLinkedMap[int, string]()

	// Add in random order
	values := []int{50, 25, 75, 10, 30, 60, 80, 5, 15, 35, 55, 65, 85}
	for _, v := range values {
		sm.PutOrdered(v, "value")
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

func TestLinkedMapPutOrderedInOrderArrival(t *testing.T) {
	// Test the O(1) fast path: in-order arrivals
	sm := NewLinkedMap[uint64, string]()

	// Simulate network packets arriving mostly in order
	for i := uint64(0); i < 1000; i++ {
		sm.PutOrdered(i*100, "data")
	}

	assert.Equal(t, 1000, sm.Size())

	// Verify sorted order
	minKey, _, ok := sm.Min()
	assert.True(t, ok)
	assert.Equal(t, uint64(0), minKey)

	// Check last
	current := minKey
	for i := 0; i < 999; i++ {
		current, _, ok = sm.Next(current)
		assert.True(t, ok)
	}
	assert.Equal(t, uint64(99900), current)
}

func TestLinkedMapPutOrderedOutOfOrderArrival(t *testing.T) {
	// Test out-of-order arrivals (packets arriving late)
	sm := NewLinkedMap[uint64, string]()

	// Add packets out of order
	offsets := []uint64{1000, 500, 1500, 250, 750, 1250, 1750}
	for _, offset := range offsets {
		sm.PutOrdered(offset, "data")
	}

	// Verify sorted order: 250, 500, 750, 1000, 1250, 1500, 1750
	expected := []uint64{250, 500, 750, 1000, 1250, 1500, 1750}
	current, _, ok := sm.Min()
	assert.True(t, ok)

	for i, exp := range expected {
		assert.Equal(t, exp, current, "Position %d", i)
		if i < len(expected)-1 {
			current, _, ok = sm.Next(current)
			assert.True(t, ok)
		}
	}
}

func TestLinkedMapPutOrderedMixedInAndOutOfOrder(t *testing.T) {
	// Realistic scenario: mostly in-order with occasional out-of-order
	sm := NewLinkedMap[uint64, string]()

	// Simulate: 0, 100, 200, 50 (late), 300, 400, 150 (late), 500
	arrivals := []uint64{0, 100, 200, 50, 300, 400, 150, 500}
	for _, offset := range arrivals {
		sm.PutOrdered(offset, "data")
	}

	// Verify sorted: 0, 50, 100, 150, 200, 300, 400, 500
	expected := []uint64{0, 50, 100, 150, 200, 300, 400, 500}
	current, _, ok := sm.Min()
	assert.True(t, ok)

	for i, exp := range expected {
		assert.Equal(t, exp, current, "Position %d", i)
		if i < len(expected)-1 {
			current, _, ok = sm.Next(current)
			assert.True(t, ok)
		}
	}
}
