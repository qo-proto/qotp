package qotp

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// CONSTRUCTOR TESTS
// =============================================================================

func TestLinkedMap_New(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	assert.NotNil(t, lm)
	assert.NotNil(t, lm.items)
	assert.NotNil(t, lm.head)
	assert.NotNil(t, lm.tail)
	assert.Equal(t, 0, lm.size)
	assert.Equal(t, lm.tail, lm.head.next)
	assert.Equal(t, lm.head, lm.tail.prev)
}

func TestLinkedMap_New_DifferentTypes(t *testing.T) {
	intMap := NewLinkedMap[int, string]()
	assert.NotNil(t, intMap)
	assert.Equal(t, 0, intMap.Size())

	uint64Map := NewLinkedMap[uint64, []byte]()
	assert.NotNil(t, uint64Map)
	assert.Equal(t, 0, uint64Map.Size())
}

// =============================================================================
// PUT TESTS (insertion order)
// =============================================================================

func TestLinkedMap_Put_Single(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("a", 1)

	assert.Equal(t, 1, lm.Size())
	v, ok := lm.Get("a")
	assert.True(t, ok)
	assert.Equal(t, 1, v)
}

func TestLinkedMap_Put_Multiple(t *testing.T) {
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

	v, ok = lm.Get("c")
	assert.True(t, ok)
	assert.Equal(t, 3, v)
}

func TestLinkedMap_Put_UpdateExisting(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("a", 1)
	lm.Put("b", 2)
	lm.Put("c", 3)

	lm.Put("b", 200)

	assert.Equal(t, 3, lm.Size(), "size should not change on update")
	v, ok := lm.Get("b")
	assert.True(t, ok)
	assert.Equal(t, 200, v)
}

func TestLinkedMap_Put_PreservesOrder(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("a", 1)
	lm.Put("b", 2)
	lm.Put("c", 3)

	// Update middle element
	lm.Put("b", 200)

	// Order should still be a -> b -> c
	k, v, ok := lm.First()
	assert.True(t, ok)
	assert.Equal(t, "a", k)
	assert.Equal(t, 1, v)

	k, v, ok = lm.Next("a")
	assert.True(t, ok)
	assert.Equal(t, "b", k)
	assert.Equal(t, 200, v)

	k, _, ok = lm.Next("b")
	assert.True(t, ok)
	assert.Equal(t, "c", k)
}

func TestLinkedMap_Put_ZeroValue(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("zero", 0)

	v, ok := lm.Get("zero")
	assert.True(t, ok)
	assert.Equal(t, 0, v)
	assert.True(t, lm.Contains("zero"))
}

// =============================================================================
// GET TESTS
// =============================================================================

func TestLinkedMap_Get_Existing(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("key", 42)

	v, ok := lm.Get("key")
	assert.True(t, ok)
	assert.Equal(t, 42, v)
}

func TestLinkedMap_Get_NonExistent(t *testing.T) {
	lm := NewLinkedMap[string, int]()

	v, ok := lm.Get("missing")
	assert.False(t, ok)
	assert.Equal(t, 0, v)
}

func TestLinkedMap_Get_EmptyMap(t *testing.T) {
	lm := NewLinkedMap[string, int]()

	v, ok := lm.Get("any")
	assert.False(t, ok)
	assert.Equal(t, 0, v)
}

// =============================================================================
// CONTAINS TESTS
// =============================================================================

func TestLinkedMap_Contains_Empty(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	assert.False(t, lm.Contains("any"))
}

func TestLinkedMap_Contains_Existing(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("key", 42)
	assert.True(t, lm.Contains("key"))
}

func TestLinkedMap_Contains_NonExistent(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("key", 42)
	assert.False(t, lm.Contains("missing"))
}

func TestLinkedMap_Contains_AfterRemove(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("key", 42)
	lm.Remove("key")
	assert.False(t, lm.Contains("key"))
}

func TestLinkedMap_Contains_ZeroValue(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("zero", 0)
	assert.True(t, lm.Contains("zero"))
}

// =============================================================================
// REMOVE TESTS
// =============================================================================

func TestLinkedMap_Remove_Empty(t *testing.T) {
	lm := NewLinkedMap[string, int]()

	_, ok := lm.Remove("any")
	assert.False(t, ok)
}

func TestLinkedMap_Remove_NonExistent(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("a", 1)

	_, ok := lm.Remove("missing")
	assert.False(t, ok)
	assert.Equal(t, 1, lm.Size())
}

func TestLinkedMap_Remove_Single(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("only", 42)

	v, ok := lm.Remove("only")
	assert.True(t, ok)
	assert.Equal(t, 42, v)
	assert.Equal(t, 0, lm.Size())
}

func TestLinkedMap_Remove_First(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("a", 1)
	lm.Put("b", 2)
	lm.Put("c", 3)

	v, ok := lm.Remove("a")
	assert.True(t, ok)
	assert.Equal(t, 1, v)
	assert.Equal(t, 2, lm.Size())

	k, _, ok := lm.First()
	assert.True(t, ok)
	assert.Equal(t, "b", k)
}

func TestLinkedMap_Remove_Middle(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("a", 1)
	lm.Put("b", 2)
	lm.Put("c", 3)

	v, ok := lm.Remove("b")
	assert.True(t, ok)
	assert.Equal(t, 2, v)
	assert.Equal(t, 2, lm.Size())

	// Verify links: a -> c
	k, _, ok := lm.Next("a")
	assert.True(t, ok)
	assert.Equal(t, "c", k)

	k, _, ok = lm.Prev("c")
	assert.True(t, ok)
	assert.Equal(t, "a", k)
}

func TestLinkedMap_Remove_Last(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("a", 1)
	lm.Put("b", 2)
	lm.Put("c", 3)

	v, ok := lm.Remove("c")
	assert.True(t, ok)
	assert.Equal(t, 3, v)
	assert.Equal(t, 2, lm.Size())

	_, _, ok = lm.Next("b")
	assert.False(t, ok)
}

// =============================================================================
// FIRST TESTS
// =============================================================================

func TestLinkedMap_First_Empty(t *testing.T) {
	lm := NewLinkedMap[string, int]()

	_, _, ok := lm.First()
	assert.False(t, ok)
}

func TestLinkedMap_First_Single(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("only", 42)

	k, v, ok := lm.First()
	assert.True(t, ok)
	assert.Equal(t, "only", k)
	assert.Equal(t, 42, v)
}

func TestLinkedMap_First_Multiple(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("first", 1)
	lm.Put("second", 2)

	k, _, _ := lm.First()
	assert.Equal(t, "first", k)
}

// =============================================================================
// NEXT TESTS
// =============================================================================

func TestLinkedMap_Next_Empty(t *testing.T) {
	lm := NewLinkedMap[string, int]()

	k, v, ok := lm.Next("any")
	assert.False(t, ok)
	assert.Equal(t, "", k)
	assert.Equal(t, 0, v)
}

func TestLinkedMap_Next_Single(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("only", 42)

	k, v, ok := lm.Next("only")
	assert.False(t, ok)
	assert.Equal(t, "", k)
	assert.Equal(t, 0, v)
}

func TestLinkedMap_Next_NonExistent(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("a", 1)

	_, _, ok := lm.Next("missing")
	assert.False(t, ok)
}

func TestLinkedMap_Next_Traverse(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("a", 1)
	lm.Put("b", 2)
	lm.Put("c", 3)

	k, v, ok := lm.Next("a")
	assert.True(t, ok)
	assert.Equal(t, "b", k)
	assert.Equal(t, 2, v)

	k, v, ok = lm.Next("b")
	assert.True(t, ok)
	assert.Equal(t, "c", k)
	assert.Equal(t, 3, v)

	_, _, ok = lm.Next("c")
	assert.False(t, ok)
}

// =============================================================================
// PREV TESTS
// =============================================================================

func TestLinkedMap_Prev_Empty(t *testing.T) {
	lm := NewLinkedMap[string, int]()

	_, _, ok := lm.Prev("any")
	assert.False(t, ok)
}

func TestLinkedMap_Prev_Single(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("only", 42)

	_, _, ok := lm.Prev("only")
	assert.False(t, ok)
}

func TestLinkedMap_Prev_NonExistent(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("a", 1)

	_, _, ok := lm.Prev("missing")
	assert.False(t, ok)
}

func TestLinkedMap_Prev_Traverse(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("a", 1)
	lm.Put("b", 2)
	lm.Put("c", 3)

	k, v, ok := lm.Prev("c")
	assert.True(t, ok)
	assert.Equal(t, "b", k)
	assert.Equal(t, 2, v)

	k, v, ok = lm.Prev("b")
	assert.True(t, ok)
	assert.Equal(t, "a", k)
	assert.Equal(t, 1, v)

	_, _, ok = lm.Prev("a")
	assert.False(t, ok)
}

func TestLinkedMap_Prev_AfterRemove(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("a", 1)
	lm.Put("b", 2)
	lm.Put("c", 3)
	lm.Put("d", 4)

	lm.Remove("b")

	k, v, ok := lm.Prev("c")
	assert.True(t, ok)
	assert.Equal(t, "a", k)
	assert.Equal(t, 1, v)
}

// =============================================================================
// REPLACE TESTS
// =============================================================================

func TestLinkedMap_Replace_NonExistent(t *testing.T) {
	lm := NewLinkedMap[string, int]()

	ok := lm.Replace("missing", "new", 0)
	assert.False(t, ok)
}

func TestLinkedMap_Replace_SameKey(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("a", 1)

	ok := lm.Replace("a", "a", 100)
	assert.True(t, ok)

	v, _ := lm.Get("a")
	assert.Equal(t, 100, v)
}

func TestLinkedMap_Replace_NewKeyExists(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("a", 1)
	lm.Put("c", 3)

	ok := lm.Replace("a", "c", 0)
	assert.False(t, ok)
}

func TestLinkedMap_Replace_Middle(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("a", 1)
	lm.Put("b", 2)
	lm.Put("c", 3)

	ok := lm.Replace("b", "B", 200)
	assert.True(t, ok)
	assert.False(t, lm.Contains("b"))
	assert.True(t, lm.Contains("B"))

	v, _ := lm.Get("B")
	assert.Equal(t, 200, v)

	// Order preserved: a -> B -> c
	k, _, _ := lm.Next("a")
	assert.Equal(t, "B", k)
	k, _, _ = lm.Next("B")
	assert.Equal(t, "c", k)
}

func TestLinkedMap_Replace_PreservesPrev(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("first", 1)
	lm.Put("second", 2)
	lm.Put("third", 3)

	lm.Replace("second", "SECOND", 200)

	k, v, ok := lm.Prev("third")
	assert.True(t, ok)
	assert.Equal(t, "SECOND", k)
	assert.Equal(t, 200, v)

	k, v, ok = lm.Prev("SECOND")
	assert.True(t, ok)
	assert.Equal(t, "first", k)
	assert.Equal(t, 1, v)
}

// =============================================================================
// SIZE TESTS
// =============================================================================

func TestLinkedMap_Size_Empty(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	assert.Equal(t, 0, lm.Size())
}

func TestLinkedMap_Size_AfterPut(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("a", 1)
	assert.Equal(t, 1, lm.Size())
	lm.Put("b", 2)
	assert.Equal(t, 2, lm.Size())
}

func TestLinkedMap_Size_AfterRemove(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("a", 1)
	lm.Put("b", 2)
	lm.Remove("a")
	assert.Equal(t, 1, lm.Size())
}

func TestLinkedMap_Size_UpdateDoesNotChange(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("a", 1)
	lm.Put("a", 100)
	assert.Equal(t, 1, lm.Size())
}

// =============================================================================
// ITERATOR TESTS
// =============================================================================

func TestLinkedMap_Iterator_Empty(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	count := 0
	for range lm.Iterator(nil) {
		count++
	}
	assert.Equal(t, 0, count)
}

func TestLinkedMap_Iterator_Single(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("single", 42)

	count := 0
	for key, value := range lm.Iterator(nil) {
		assert.Equal(t, "single", key)
		assert.Equal(t, 42, value)
		count++
	}
	assert.Equal(t, 1, count)
}

func TestLinkedMap_Iterator_Multiple(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("first", 1)
	lm.Put("second", 2)
	lm.Put("third", 3)

	expected := []string{"first", "second", "third"}
	i := 0
	for key, value := range lm.Iterator(nil) {
		assert.Equal(t, expected[i], key)
		assert.Equal(t, i+1, value)
		i++
	}
	assert.Equal(t, 3, i)
}

func TestLinkedMap_Iterator_WithStartKey(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("first", 1)
	lm.Put("second", 2)
	lm.Put("third", 3)

	second := "second"
	count := 0
	for key, value := range lm.Iterator(&second) {
		assert.Equal(t, "third", key)
		assert.Equal(t, 3, value)
		count++
	}
	assert.Equal(t, 1, count)
}

func TestLinkedMap_Iterator_WithNonExistentStartKey(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("first", 1)
	lm.Put("second", 2)

	nonExistent := "nonexistent"
	count := 0
	for range lm.Iterator(&nonExistent) {
		count++
	}
	// Should iterate from beginning when start key doesn't exist
	assert.Equal(t, 2, count)
}

func TestLinkedMap_Iterator_PreservesInsertionOrder(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	// Add out of alphabetical order
	lm.Put("z", 26)
	lm.Put("a", 1)
	lm.Put("m", 13)

	expected := []string{"z", "a", "m"}
	i := 0
	for key := range lm.Iterator(nil) {
		assert.Equal(t, expected[i], key)
		i++
	}
}

func TestLinkedMap_Iterator_AfterRemovals(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("a", 1)
	lm.Put("b", 2)
	lm.Put("c", 3)
	lm.Put("d", 4)

	lm.Remove("b")

	expected := []string{"a", "c", "d"}
	i := 0
	for key := range lm.Iterator(nil) {
		assert.Equal(t, expected[i], key)
		i++
	}
	assert.Equal(t, 3, i)
}

func TestLinkedMap_Iterator_StartKeyIsLast(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("a", 1)
	lm.Put("b", 2)
	lm.Put("c", 3)

	last := "c"
	count := 0
	for range lm.Iterator(&last) {
		count++
	}
	// When startKey is last element, node.next == tail, so iterator falls back to beginning
	assert.Equal(t, 3, count)
}

// =============================================================================
// BIDIRECTIONAL TRAVERSAL TESTS
// =============================================================================

func TestLinkedMap_BidirectionalTraversal(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	lm.Put("a", 1)
	lm.Put("b", 2)
	lm.Put("c", 3)
	lm.Put("d", 4)

	// Forward
	k, v, ok := lm.First()
	assert.True(t, ok)
	assert.Equal(t, "a", k)
	assert.Equal(t, 1, v)

	k, _, _ = lm.Next("a")
	assert.Equal(t, "b", k)
	k, _, _ = lm.Next("b")
	assert.Equal(t, "c", k)

	// Backward from c
	k, v, ok = lm.Prev("c")
	assert.True(t, ok)
	assert.Equal(t, "b", k)
	assert.Equal(t, 2, v)

	k, _, _ = lm.Prev("b")
	assert.Equal(t, "a", k)
}

// =============================================================================
// PUTORDERED TESTS (sorted order)
// =============================================================================

func TestLinkedMap_PutOrdered_Empty(t *testing.T) {
	sm := NewLinkedMap[int, string]()

	assert.Equal(t, 0, sm.Size())
	_, _, ok := sm.First()
	assert.False(t, ok)
}

func TestLinkedMap_PutOrdered_Single(t *testing.T) {
	sm := NewLinkedMap[int, string]()
	sm.PutOrdered(5, "five")

	v, ok := sm.Get(5)
	assert.True(t, ok)
	assert.Equal(t, "five", v)
	assert.Equal(t, 1, sm.Size())
}

func TestLinkedMap_PutOrdered_UpdateExisting(t *testing.T) {
	sm := NewLinkedMap[int, string]()
	sm.PutOrdered(1, "one")
	sm.PutOrdered(1, "ONE")

	v, _ := sm.Get(1)
	assert.Equal(t, "ONE", v)
	assert.Equal(t, 1, sm.Size())
}

func TestLinkedMap_PutOrdered_MaintainsSortedOrder(t *testing.T) {
	sm := NewLinkedMap[int, string]()
	sm.PutOrdered(5, "five")
	sm.PutOrdered(3, "three")
	sm.PutOrdered(7, "seven")
	sm.PutOrdered(1, "one")
	sm.PutOrdered(9, "nine")

	expected := []int{1, 3, 5, 7, 9}
	k, _, ok := sm.First()
	assert.True(t, ok)

	for i, exp := range expected {
		assert.Equal(t, exp, k, "position %d", i)
		if i < len(expected)-1 {
			k, _, ok = sm.Next(k)
			assert.True(t, ok)
		}
	}
}

func TestLinkedMap_PutOrdered_InOrder(t *testing.T) {
	// Test O(1) fast path for in-order arrivals
	sm := NewLinkedMap[uint64, string]()

	for i := uint64(0); i < 100; i++ {
		sm.PutOrdered(i*100, "data")
	}

	assert.Equal(t, 100, sm.Size())

	k, _, ok := sm.First()
	assert.True(t, ok)
	assert.Equal(t, uint64(0), k)
}

func TestLinkedMap_PutOrdered_OutOfOrder(t *testing.T) {
	sm := NewLinkedMap[uint64, string]()

	offsets := []uint64{1000, 500, 1500, 250, 750}
	for _, offset := range offsets {
		sm.PutOrdered(offset, "data")
	}

	expected := []uint64{250, 500, 750, 1000, 1500}
	k, _, ok := sm.First()
	assert.True(t, ok)

	for i, exp := range expected {
		assert.Equal(t, exp, k, "position %d", i)
		if i < len(expected)-1 {
			k, _, ok = sm.Next(k)
			assert.True(t, ok)
		}
	}
}

func TestLinkedMap_PutOrdered_MixedOrder(t *testing.T) {
	sm := NewLinkedMap[uint64, string]()

	// Simulate mostly in-order with occasional late arrivals
	arrivals := []uint64{0, 100, 200, 50, 300, 400, 150, 500}
	for _, offset := range arrivals {
		sm.PutOrdered(offset, "data")
	}

	expected := []uint64{0, 50, 100, 150, 200, 300, 400, 500}
	k, _, ok := sm.First()
	assert.True(t, ok)

	for i, exp := range expected {
		assert.Equal(t, exp, k, "position %d", i)
		if i < len(expected)-1 {
			k, _, ok = sm.Next(k)
			assert.True(t, ok)
		}
	}
}

func TestLinkedMap_PutOrdered_Prev(t *testing.T) {
	sm := NewLinkedMap[int, string]()
	for _, v := range []int{1, 5, 10, 20, 50} {
		sm.PutOrdered(v, "val")
	}

	k, _, ok := sm.Prev(20)
	assert.True(t, ok)
	assert.Equal(t, 10, k)

	k, _, ok = sm.Prev(10)
	assert.True(t, ok)
	assert.Equal(t, 5, k)

	_, _, ok = sm.Prev(1)
	assert.False(t, ok)

	// Non-existent key
	_, _, ok = sm.Prev(15)
	assert.False(t, ok)
}

func TestLinkedMap_PutOrdered_Next(t *testing.T) {
	sm := NewLinkedMap[int, string]()
	for _, v := range []int{1, 3, 5, 7, 9} {
		sm.PutOrdered(v, "val")
	}

	k, _, ok := sm.Next(3)
	assert.True(t, ok)
	assert.Equal(t, 5, k)

	_, _, ok = sm.Next(9)
	assert.False(t, ok)

	// Non-existent key
	_, _, ok = sm.Next(4)
	assert.False(t, ok)
}

func TestLinkedMap_PutOrdered_RemoveAndAdd(t *testing.T) {
	sm := NewLinkedMap[int, string]()
	sm.PutOrdered(1, "one")
	sm.PutOrdered(2, "two")
	sm.PutOrdered(3, "three")

	sm.Remove(1)
	sm.Remove(2)
	sm.Remove(3)
	assert.Equal(t, 0, sm.Size())

	sm.PutOrdered(5, "five")
	sm.PutOrdered(10, "ten")

	k, _, ok := sm.First()
	assert.True(t, ok)
	assert.Equal(t, 5, k)
}

func TestLinkedMap_PutOrdered_IntegrityAfterRemoves(t *testing.T) {
	sm := NewLinkedMap[int, string]()

	values := []int{50, 25, 75, 10, 30, 60, 80}
	for _, v := range values {
		sm.PutOrdered(v, "value")
	}

	sm.Remove(25)
	sm.Remove(60)

	// Forward traversal
	expected := []int{10, 30, 50, 75, 80}
	k, _, ok := sm.First()
	assert.True(t, ok)

	for i, exp := range expected {
		assert.Equal(t, exp, k)
		if i < len(expected)-1 {
			k, _, ok = sm.Next(k)
			assert.True(t, ok)
		}
	}

	// Backward traversal
	for i := len(expected) - 1; i >= 0; i-- {
		assert.Equal(t, expected[i], k)
		if i > 0 {
			k, _, ok = sm.Prev(k)
			assert.True(t, ok)
		}
	}
}

// =============================================================================
// CONCURRENT TESTS
// =============================================================================

func TestLinkedMap_Concurrent_Reads(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	keys := make([]string, 100)
	for i := 0; i < 100; i++ {
		key := "key" + strconv.Itoa(i)
		keys[i] = key
		lm.Put(key, i)
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				key := keys[j]
				_, _ = lm.Get(key)
				_ = lm.Contains(key)
				_ = lm.Size()
				_, _, _ = lm.Next(key)
				_, _, _ = lm.Prev(key)
				_, _, _ = lm.First()
			}
		}()
	}

	wg.Wait()
	assert.Equal(t, 100, lm.Size())
}

func TestLinkedMap_Concurrent_Writes(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	var wg sync.WaitGroup

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			baseKey := "goroutine" + strconv.Itoa(id) + "_"
			for j := 0; j < 20; j++ {
				key := baseKey + strconv.Itoa(j)
				lm.Put(key, id*1000+j)
			}
		}(i)
	}

	wg.Wait()
	assert.Equal(t, 100, lm.Size())
}

func TestLinkedMap_Concurrent_Mixed(t *testing.T) {
	lm := NewLinkedMap[string, int]()
	keys := make([]string, 50)
	for i := 0; i < 50; i++ {
		key := "key" + strconv.Itoa(i)
		keys[i] = key
		lm.Put(key, i)
	}

	var wg sync.WaitGroup

	// Readers
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

	// Writers
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 30; j++ {
				key := "writer" + strconv.Itoa(id) + "_" + strconv.Itoa(j)
				lm.Put(key, id*1000+j)
				if j%5 == 0 {
					time.Sleep(time.Microsecond)
				}
			}
		}(i)
	}

	wg.Wait()
	assert.True(t, lm.Size() >= 50)
	assert.True(t, lm.Size() <= 110)
}

func TestLinkedMap_Concurrent_PutOrdered(t *testing.T) {
	sm := NewLinkedMap[int, string]()
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				val := base*100 + j
				sm.PutOrdered(val, "value")
			}
		}(i)
	}

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
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