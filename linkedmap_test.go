package qotp

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

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
	assert.Equal(t, 1, lm.Get("a"))
	assert.Equal(t, 2, lm.Get("b"))
	
	// Update existing key - size unchanged, order preserved
	lm.Put("b", 200)
	assert.Equal(t, 3, lm.Size())
	assert.Equal(t, 200, lm.Get("b"))
	
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
	
	// Non-existent returns zero value
	assert.Equal(t, 0, lm.Get("missing"))
	
	// Existing key
	lm.Put("key", 42)
	assert.Equal(t, 42, lm.Get("key"))
	
	// Zero value is distinguishable via Contains
	lm.Put("zero", 0)
	assert.Equal(t, 0, lm.Get("zero"))
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

func TestLinkedMapPrevious(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	
	lm.Put("a", 1)
	lm.Put("b", 2)
	lm.Put("c", 3)
	
	k, v, ok := lm.Previous("c")
	assert.True(t, ok)
	assert.Equal(t, "b", k)
	assert.Equal(t, 2, v)
	
	// First element has no previous
	_, _, ok = lm.Previous("a")
	assert.False(t, ok)
	
	// Non-existent key
	_, _, ok = lm.Previous("missing")
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
	assert.Equal(t, 200, lm.Get("B"))
	
	// Order preserved: a -> B -> c
	k, _, _ := lm.Next("a")
	assert.Equal(t, "B", k)
	k, _, _ = lm.Next("B")
	assert.Equal(t, "c", k)
	
	// Replace with same key (just update value)
	ok = lm.Replace("a", "a", 100)
	assert.True(t, ok)
	assert.Equal(t, 100, lm.Get("a"))
	
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
	
	expected := []struct{ key string; value int }{
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
	expected := []struct{ key string; value int }{
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
	expected := []struct{ key string; value int }{
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
	
	expected := []struct{ key string; value int }{
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
	
	// Remove middle elements
	_, ok := lm.Remove(b)
	assert.True(t, ok)
	_, ok = lm.Remove(c)
	assert.True(t, ok)
	
	expected := []struct{ key string; value int }{
		{a, 1},
		{d, 4},
	}
	
	i := 0
	for key, value := range lm.Iterator(nil) {
		assert.Equal(t, expected[i].key, key)
		assert.Equal(t, expected[i].value, value)
		i++
	}
	assert.Equal(t, 2, i)
}

func TestLinkedMapIteratorAfterReplace(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	first := "first"
	second := "second"
	third := "third"
	SECOND := "SECOND"
	
	lm.Put(first, 1)
	lm.Put(second, 2)
	lm.Put(third, 3)
	
	// Replace middle element
	lm.Replace(second, SECOND, 200)
	
	expected := []struct{ key string; value int }{
		{first, 1},
		{SECOND, 200},
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

func TestLinkedMapIteratorBreakEarly(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	for i := 0; i < 10; i++ {
		lm.Put(strconv.Itoa(i), i)
	}
	
	count := 0
	for key, value := range lm.Iterator(nil) {
		_ = key
		_ = value
		count++
		if count == 5 {
			break // Test early break
		}
	}
	assert.Equal(t, 5, count)
}

func TestLinkedMapIteratorFullTraversal(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	// Add many elements
	expected := make(map[string]int)
	keys := []string{"alpha", "beta", "gamma", "delta", "epsilon"}
	
	for i, key := range keys {
		value := (i + 1) * 10
		lm.Put(key, value)
		expected[key] = value
	}
	
	// Traverse with iterator
	collected := make(map[string]int)
	collectedOrder := make([]string, 0)
	
	for key, value := range lm.Iterator(nil) {
		collected[key] = value
		collectedOrder = append(collectedOrder, key)
	}
	
	// Verify all elements collected
	assert.Equal(t, len(expected), len(collected))
	for key, expectedValue := range expected {
		actualValue, exists := collected[key]
		assert.True(t, exists, "Key %s should exist", key)
		assert.Equal(t, expectedValue, actualValue, "Value for key %s", key)
	}
	
	// Verify order matches insertion order
	assert.Equal(t, keys, collectedOrder)
}

func TestLinkedMapComplexOperations(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	// Add some elements
	a := "a"
	b := "b"
	c := "c"
	d := "d"
	
	lm.Put(a, 1)
	lm.Put(b, 2)
	lm.Put(c, 3)
	
	// Update one
	lm.Put(b, 20)
	
	// Remove one
	_, ok := lm.Remove(a)
	assert.True(t, ok)
	
	// Add another
	lm.Put(d, 4)
	
	// Check final state
	assert.Equal(t, 3, lm.Size())
	
	key, value, ok := lm.First()
	assert.True(t, ok)
	assert.Equal(t, b, key)
	assert.Equal(t, 20, value)
	
	key, value, ok = lm.Next(b)
	assert.True(t, ok)
	assert.Equal(t, c, key)
	assert.Equal(t, 3, value)
	
	key, value, ok = lm.Next(c)
	assert.True(t, ok)
	assert.Equal(t, d, key)
	assert.Equal(t, 4, value)
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
	expected := []struct{ key string; value int }{
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
	
	assert.Equal(t, "world", strMap.Get(hello))
	assert.Equal(t, "bar", strMap.Get(foo))
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
	assert.Equal(t, 42, lm.Get(single))
	
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
	key, value, ok = lm.Previous(c)
	assert.True(t, ok)
	assert.Equal(t, b, key)
	assert.Equal(t, 2, value)
	
	key, value, ok = lm.Previous(b)
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
	key, value, ok := lm.Previous(c)
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
	key, value, ok := lm.Previous(third)
	assert.True(t, ok)
	assert.Equal(t, SECOND, key)
	assert.Equal(t, 200, value)
	
	key, value, ok = lm.Previous(SECOND)
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
				
				_ = lm.Get(key)
				_ = lm.Contains(key)
				_ = lm.Size()
				
				if lm.Contains(key) {
					_, _, _ = lm.Next(key)
					_, _, _ = lm.Previous(key)
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
				_ = lm.Get(key)
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
	assert.True(t, lm.Size() >= 50) // At least original elements
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
	expected := []struct{ outer *LinkedMap[string, int]; inner int }{
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
	expected := []struct{ outer *LinkedMap[string, int]; inner int }{
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