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
	lm := newLinkedMap[string, int]()
	assert.NotNil(t, lm)
	assert.NotNil(t, lm.items)
	assert.NotNil(t, lm.head)
	assert.NotNil(t, lm.tail)
	assert.Equal(t, 0, lm.len)
	assert.Equal(t, lm.tail, lm.head.next)
	assert.Equal(t, lm.head, lm.tail.prev)
}

func TestLinkedMap_New_DifferentTypes(t *testing.T) {
	intMap := newLinkedMap[int, string]()
	assert.NotNil(t, intMap)
	assert.Equal(t, 0, intMap.size())

	uint64Map := newLinkedMap[uint64, []byte]()
	assert.NotNil(t, uint64Map)
	assert.Equal(t, 0, uint64Map.size())
}

// =============================================================================
// PUT TESTS (insertion order)
// =============================================================================

func TestLinkedMap_Put_Single(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("a", 1)

	assert.Equal(t, 1, lm.size())
	v, ok := lm.get("a")
	assert.True(t, ok)
	assert.Equal(t, 1, v)
}

func TestLinkedMap_Put_Multiple(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("a", 1)
	lm.put("b", 2)
	lm.put("c", 3)

	assert.Equal(t, 3, lm.size())

	v, ok := lm.get("a")
	assert.True(t, ok)
	assert.Equal(t, 1, v)

	v, ok = lm.get("b")
	assert.True(t, ok)
	assert.Equal(t, 2, v)

	v, ok = lm.get("c")
	assert.True(t, ok)
	assert.Equal(t, 3, v)
}

func TestLinkedMap_Put_UpdateExisting(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("a", 1)
	lm.put("b", 2)
	lm.put("c", 3)

	lm.put("b", 200)

	assert.Equal(t, 3, lm.size(), "size should not change on update")
	v, ok := lm.get("b")
	assert.True(t, ok)
	assert.Equal(t, 200, v)
}

func TestLinkedMap_Put_PreservesOrder(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("a", 1)
	lm.put("b", 2)
	lm.put("c", 3)

	// Update middle element
	lm.put("b", 200)

	// Order should still be a -> b -> c
	k, v, ok := lm.first()
	assert.True(t, ok)
	assert.Equal(t, "a", k)
	assert.Equal(t, 1, v)

	k, v, ok = lm.next("a")
	assert.True(t, ok)
	assert.Equal(t, "b", k)
	assert.Equal(t, 200, v)

	k, _, ok = lm.next("b")
	assert.True(t, ok)
	assert.Equal(t, "c", k)
}

func TestLinkedMap_Put_ZeroValue(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("zero", 0)

	v, ok := lm.get("zero")
	assert.True(t, ok)
	assert.Equal(t, 0, v)
	assert.True(t, lm.contains("zero"))
}

// =============================================================================
// GET TESTS
// =============================================================================

func TestLinkedMap_Get_Existing(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("key", 42)

	v, ok := lm.get("key")
	assert.True(t, ok)
	assert.Equal(t, 42, v)
}

func TestLinkedMap_Get_NonExistent(t *testing.T) {
	lm := newLinkedMap[string, int]()

	v, ok := lm.get("missing")
	assert.False(t, ok)
	assert.Equal(t, 0, v)
}

func TestLinkedMap_Get_EmptyMap(t *testing.T) {
	lm := newLinkedMap[string, int]()

	v, ok := lm.get("any")
	assert.False(t, ok)
	assert.Equal(t, 0, v)
}

// =============================================================================
// CONTAINS TESTS
// =============================================================================

func TestLinkedMap_Contains_Empty(t *testing.T) {
	lm := newLinkedMap[string, int]()
	assert.False(t, lm.contains("any"))
}

func TestLinkedMap_Contains_Existing(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("key", 42)
	assert.True(t, lm.contains("key"))
}

func TestLinkedMap_Contains_NonExistent(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("key", 42)
	assert.False(t, lm.contains("missing"))
}

func TestLinkedMap_Contains_AfterRemove(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("key", 42)
	lm.remove("key")
	assert.False(t, lm.contains("key"))
}

func TestLinkedMap_Contains_ZeroValue(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("zero", 0)
	assert.True(t, lm.contains("zero"))
}

// =============================================================================
// REMOVE TESTS
// =============================================================================

func TestLinkedMap_Remove_Empty(t *testing.T) {
	lm := newLinkedMap[string, int]()

	_, ok := lm.remove("any")
	assert.False(t, ok)
}

func TestLinkedMap_Remove_NonExistent(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("a", 1)

	_, ok := lm.remove("missing")
	assert.False(t, ok)
	assert.Equal(t, 1, lm.size())
}

func TestLinkedMap_Remove_Single(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("only", 42)

	v, ok := lm.remove("only")
	assert.True(t, ok)
	assert.Equal(t, 42, v)
	assert.Equal(t, 0, lm.size())
}

func TestLinkedMap_Remove_First(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("a", 1)
	lm.put("b", 2)
	lm.put("c", 3)

	v, ok := lm.remove("a")
	assert.True(t, ok)
	assert.Equal(t, 1, v)
	assert.Equal(t, 2, lm.size())

	k, _, ok := lm.first()
	assert.True(t, ok)
	assert.Equal(t, "b", k)
}

func TestLinkedMap_Remove_Middle(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("a", 1)
	lm.put("b", 2)
	lm.put("c", 3)

	v, ok := lm.remove("b")
	assert.True(t, ok)
	assert.Equal(t, 2, v)
	assert.Equal(t, 2, lm.size())

	// Verify links: a -> c
	k, _, ok := lm.next("a")
	assert.True(t, ok)
	assert.Equal(t, "c", k)

	k, _, ok = lm.prev("c")
	assert.True(t, ok)
	assert.Equal(t, "a", k)
}

func TestLinkedMap_Remove_Last(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("a", 1)
	lm.put("b", 2)
	lm.put("c", 3)

	v, ok := lm.remove("c")
	assert.True(t, ok)
	assert.Equal(t, 3, v)
	assert.Equal(t, 2, lm.size())

	_, _, ok = lm.next("b")
	assert.False(t, ok)
}

// =============================================================================
// FIRST TESTS
// =============================================================================

func TestLinkedMap_First_Empty(t *testing.T) {
	lm := newLinkedMap[string, int]()

	_, _, ok := lm.first()
	assert.False(t, ok)
}

func TestLinkedMap_First_Single(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("only", 42)

	k, v, ok := lm.first()
	assert.True(t, ok)
	assert.Equal(t, "only", k)
	assert.Equal(t, 42, v)
}

func TestLinkedMap_First_Multiple(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("first", 1)
	lm.put("second", 2)

	k, _, _ := lm.first()
	assert.Equal(t, "first", k)
}

// =============================================================================
// NEXT TESTS
// =============================================================================

func TestLinkedMap_Next_Empty(t *testing.T) {
	lm := newLinkedMap[string, int]()

	k, v, ok := lm.next("any")
	assert.False(t, ok)
	assert.Equal(t, "", k)
	assert.Equal(t, 0, v)
}

func TestLinkedMap_Next_Single(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("only", 42)

	k, v, ok := lm.next("only")
	assert.False(t, ok)
	assert.Equal(t, "", k)
	assert.Equal(t, 0, v)
}

func TestLinkedMap_Next_NonExistent(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("a", 1)

	_, _, ok := lm.next("missing")
	assert.False(t, ok)
}

func TestLinkedMap_Next_Traverse(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("a", 1)
	lm.put("b", 2)
	lm.put("c", 3)

	k, v, ok := lm.next("a")
	assert.True(t, ok)
	assert.Equal(t, "b", k)
	assert.Equal(t, 2, v)

	k, v, ok = lm.next("b")
	assert.True(t, ok)
	assert.Equal(t, "c", k)
	assert.Equal(t, 3, v)

	_, _, ok = lm.next("c")
	assert.False(t, ok)
}

// =============================================================================
// PREV TESTS
// =============================================================================

func TestLinkedMap_Prev_Empty(t *testing.T) {
	lm := newLinkedMap[string, int]()

	_, _, ok := lm.prev("any")
	assert.False(t, ok)
}

func TestLinkedMap_Prev_Single(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("only", 42)

	_, _, ok := lm.prev("only")
	assert.False(t, ok)
}

func TestLinkedMap_Prev_NonExistent(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("a", 1)

	_, _, ok := lm.prev("missing")
	assert.False(t, ok)
}

func TestLinkedMap_Prev_Traverse(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("a", 1)
	lm.put("b", 2)
	lm.put("c", 3)

	k, v, ok := lm.prev("c")
	assert.True(t, ok)
	assert.Equal(t, "b", k)
	assert.Equal(t, 2, v)

	k, v, ok = lm.prev("b")
	assert.True(t, ok)
	assert.Equal(t, "a", k)
	assert.Equal(t, 1, v)

	_, _, ok = lm.prev("a")
	assert.False(t, ok)
}

func TestLinkedMap_Prev_AfterRemove(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("a", 1)
	lm.put("b", 2)
	lm.put("c", 3)
	lm.put("d", 4)

	lm.remove("b")

	k, v, ok := lm.prev("c")
	assert.True(t, ok)
	assert.Equal(t, "a", k)
	assert.Equal(t, 1, v)
}

// =============================================================================
// REPLACE TESTS
// =============================================================================

func TestLinkedMap_Replace_NonExistent(t *testing.T) {
	lm := newLinkedMap[string, int]()

	ok := lm.replace("missing", "new", 0)
	assert.False(t, ok)
}

func TestLinkedMap_Replace_SameKey(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("a", 1)

	ok := lm.replace("a", "a", 100)
	assert.True(t, ok)

	v, _ := lm.get("a")
	assert.Equal(t, 100, v)
}

func TestLinkedMap_Replace_NewKeyExists(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("a", 1)
	lm.put("c", 3)

	ok := lm.replace("a", "c", 0)
	assert.False(t, ok)
}

func TestLinkedMap_Replace_Middle(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("a", 1)
	lm.put("b", 2)
	lm.put("c", 3)

	ok := lm.replace("b", "B", 200)
	assert.True(t, ok)
	assert.False(t, lm.contains("b"))
	assert.True(t, lm.contains("B"))

	v, _ := lm.get("B")
	assert.Equal(t, 200, v)

	// Order preserved: a -> B -> c
	k, _, _ := lm.next("a")
	assert.Equal(t, "B", k)
	k, _, _ = lm.next("B")
	assert.Equal(t, "c", k)
}

func TestLinkedMap_Replace_PreservesPrev(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("first", 1)
	lm.put("second", 2)
	lm.put("third", 3)

	lm.replace("second", "SECOND", 200)

	k, v, ok := lm.prev("third")
	assert.True(t, ok)
	assert.Equal(t, "SECOND", k)
	assert.Equal(t, 200, v)

	k, v, ok = lm.prev("SECOND")
	assert.True(t, ok)
	assert.Equal(t, "first", k)
	assert.Equal(t, 1, v)
}

// =============================================================================
// SIZE TESTS
// =============================================================================

func TestLinkedMap_Size_Empty(t *testing.T) {
	lm := newLinkedMap[string, int]()
	assert.Equal(t, 0, lm.size())
}

func TestLinkedMap_Size_AfterPut(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("a", 1)
	assert.Equal(t, 1, lm.size())
	lm.put("b", 2)
	assert.Equal(t, 2, lm.size())
}

func TestLinkedMap_Size_AfterRemove(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("a", 1)
	lm.put("b", 2)
	lm.remove("a")
	assert.Equal(t, 1, lm.size())
}

func TestLinkedMap_Size_UpdateDoesNotChange(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("a", 1)
	lm.put("a", 100)
	assert.Equal(t, 1, lm.size())
}

// =============================================================================
// ITERATOR TESTS
// =============================================================================

func TestLinkedMap_Iterator_Empty(t *testing.T) {
	lm := newLinkedMap[string, int]()
	count := 0
	for range lm.iterator(nil) {
		count++
	}
	assert.Equal(t, 0, count)
}

func TestLinkedMap_Iterator_Single(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("single", 42)

	count := 0
	for key, value := range lm.iterator(nil) {
		assert.Equal(t, "single", key)
		assert.Equal(t, 42, value)
		count++
	}
	assert.Equal(t, 1, count)
}

func TestLinkedMap_Iterator_Multiple(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("first", 1)
	lm.put("second", 2)
	lm.put("third", 3)

	expected := []string{"first", "second", "third"}
	i := 0
	for key, value := range lm.iterator(nil) {
		assert.Equal(t, expected[i], key)
		assert.Equal(t, i+1, value)
		i++
	}
	assert.Equal(t, 3, i)
}

func TestLinkedMap_Iterator_WithStartKey(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("first", 1)
	lm.put("second", 2)
	lm.put("third", 3)

	second := "second"
	count := 0
	for key, value := range lm.iterator(&second) {
		assert.Equal(t, "third", key)
		assert.Equal(t, 3, value)
		count++
	}
	assert.Equal(t, 1, count)
}

func TestLinkedMap_Iterator_WithNonExistentStartKey(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("first", 1)
	lm.put("second", 2)

	nonExistent := "nonexistent"
	count := 0
	for range lm.iterator(&nonExistent) {
		count++
	}
	// Should iterate from beginning when start key doesn't exist
	assert.Equal(t, 2, count)
}

func TestLinkedMap_Iterator_PreservesInsertionOrder(t *testing.T) {
	lm := newLinkedMap[string, int]()
	// Add out of alphabetical order
	lm.put("z", 26)
	lm.put("a", 1)
	lm.put("m", 13)

	expected := []string{"z", "a", "m"}
	i := 0
	for key := range lm.iterator(nil) {
		assert.Equal(t, expected[i], key)
		i++
	}
}

func TestLinkedMap_Iterator_AfterRemovals(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("a", 1)
	lm.put("b", 2)
	lm.put("c", 3)
	lm.put("d", 4)

	lm.remove("b")

	expected := []string{"a", "c", "d"}
	i := 0
	for key := range lm.iterator(nil) {
		assert.Equal(t, expected[i], key)
		i++
	}
	assert.Equal(t, 3, i)
}

func TestLinkedMap_Iterator_StartKeyIsLast(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("a", 1)
	lm.put("b", 2)
	lm.put("c", 3)

	last := "c"
	count := 0
	for range lm.iterator(&last) {
		count++
	}
	// When startKey is last element, node.next == tail, so iterator falls back to beginning
	assert.Equal(t, 3, count)
}

// =============================================================================
// BIDIRECTIONAL TRAVERSAL TESTS
// =============================================================================

func TestLinkedMap_BidirectionalTraversal(t *testing.T) {
	lm := newLinkedMap[string, int]()
	lm.put("a", 1)
	lm.put("b", 2)
	lm.put("c", 3)
	lm.put("d", 4)

	// Forward
	k, v, ok := lm.first()
	assert.True(t, ok)
	assert.Equal(t, "a", k)
	assert.Equal(t, 1, v)

	k, _, _ = lm.next("a")
	assert.Equal(t, "b", k)
	k, _, _ = lm.next("b")
	assert.Equal(t, "c", k)

	// Backward from c
	k, v, ok = lm.prev("c")
	assert.True(t, ok)
	assert.Equal(t, "b", k)
	assert.Equal(t, 2, v)

	k, _, _ = lm.prev("b")
	assert.Equal(t, "a", k)
}

// =============================================================================
// PUTORDERED TESTS (sorted order)
// =============================================================================

func TestLinkedMap_PutOrdered_Empty(t *testing.T) {
	sm := newLinkedMap[int, string]()

	assert.Equal(t, 0, sm.size())
	_, _, ok := sm.first()
	assert.False(t, ok)
}

func TestLinkedMap_PutOrdered_Single(t *testing.T) {
	sm := newLinkedMap[int, string]()
	sm.putOrdered(5, "five")

	v, ok := sm.get(5)
	assert.True(t, ok)
	assert.Equal(t, "five", v)
	assert.Equal(t, 1, sm.size())
}

func TestLinkedMap_PutOrdered_UpdateExisting(t *testing.T) {
	sm := newLinkedMap[int, string]()
	sm.putOrdered(1, "one")
	sm.putOrdered(1, "ONE")

	v, _ := sm.get(1)
	assert.Equal(t, "ONE", v)
	assert.Equal(t, 1, sm.size())
}

func TestLinkedMap_PutOrdered_MaintainsSortedOrder(t *testing.T) {
	sm := newLinkedMap[int, string]()
	sm.putOrdered(5, "five")
	sm.putOrdered(3, "three")
	sm.putOrdered(7, "seven")
	sm.putOrdered(1, "one")
	sm.putOrdered(9, "nine")

	expected := []int{1, 3, 5, 7, 9}
	k, _, ok := sm.first()
	assert.True(t, ok)

	for i, exp := range expected {
		assert.Equal(t, exp, k, "position %d", i)
		if i < len(expected)-1 {
			k, _, ok = sm.next(k)
			assert.True(t, ok)
		}
	}
}

func TestLinkedMap_PutOrdered_InOrder(t *testing.T) {
	// Test O(1) fast path for in-order arrivals
	sm := newLinkedMap[uint64, string]()

	for i := uint64(0); i < 100; i++ {
		sm.putOrdered(i*100, "data")
	}

	assert.Equal(t, 100, sm.size())

	k, _, ok := sm.first()
	assert.True(t, ok)
	assert.Equal(t, uint64(0), k)
}

func TestLinkedMap_PutOrdered_OutOfOrder(t *testing.T) {
	sm := newLinkedMap[uint64, string]()

	offsets := []uint64{1000, 500, 1500, 250, 750}
	for _, offset := range offsets {
		sm.putOrdered(offset, "data")
	}

	expected := []uint64{250, 500, 750, 1000, 1500}
	k, _, ok := sm.first()
	assert.True(t, ok)

	for i, exp := range expected {
		assert.Equal(t, exp, k, "position %d", i)
		if i < len(expected)-1 {
			k, _, ok = sm.next(k)
			assert.True(t, ok)
		}
	}
}

func TestLinkedMap_PutOrdered_MixedOrder(t *testing.T) {
	sm := newLinkedMap[uint64, string]()

	// Simulate mostly in-order with occasional late arrivals
	arrivals := []uint64{0, 100, 200, 50, 300, 400, 150, 500}
	for _, offset := range arrivals {
		sm.putOrdered(offset, "data")
	}

	expected := []uint64{0, 50, 100, 150, 200, 300, 400, 500}
	k, _, ok := sm.first()
	assert.True(t, ok)

	for i, exp := range expected {
		assert.Equal(t, exp, k, "position %d", i)
		if i < len(expected)-1 {
			k, _, ok = sm.next(k)
			assert.True(t, ok)
		}
	}
}

func TestLinkedMap_PutOrdered_Prev(t *testing.T) {
	sm := newLinkedMap[int, string]()
	for _, v := range []int{1, 5, 10, 20, 50} {
		sm.putOrdered(v, "val")
	}

	k, _, ok := sm.prev(20)
	assert.True(t, ok)
	assert.Equal(t, 10, k)

	k, _, ok = sm.prev(10)
	assert.True(t, ok)
	assert.Equal(t, 5, k)

	_, _, ok = sm.prev(1)
	assert.False(t, ok)

	// Non-existent key
	_, _, ok = sm.prev(15)
	assert.False(t, ok)
}

func TestLinkedMap_PutOrdered_Next(t *testing.T) {
	sm := newLinkedMap[int, string]()
	for _, v := range []int{1, 3, 5, 7, 9} {
		sm.putOrdered(v, "val")
	}

	k, _, ok := sm.next(3)
	assert.True(t, ok)
	assert.Equal(t, 5, k)

	_, _, ok = sm.next(9)
	assert.False(t, ok)

	// Non-existent key
	_, _, ok = sm.next(4)
	assert.False(t, ok)
}

func TestLinkedMap_PutOrdered_RemoveAndAdd(t *testing.T) {
	sm := newLinkedMap[int, string]()
	sm.putOrdered(1, "one")
	sm.putOrdered(2, "two")
	sm.putOrdered(3, "three")

	sm.remove(1)
	sm.remove(2)
	sm.remove(3)
	assert.Equal(t, 0, sm.size())

	sm.putOrdered(5, "five")
	sm.putOrdered(10, "ten")

	k, _, ok := sm.first()
	assert.True(t, ok)
	assert.Equal(t, 5, k)
}

func TestLinkedMap_PutOrdered_IntegrityAfterRemoves(t *testing.T) {
	sm := newLinkedMap[int, string]()

	values := []int{50, 25, 75, 10, 30, 60, 80}
	for _, v := range values {
		sm.putOrdered(v, "value")
	}

	sm.remove(25)
	sm.remove(60)

	// Forward traversal
	expected := []int{10, 30, 50, 75, 80}
	k, _, ok := sm.first()
	assert.True(t, ok)

	for i, exp := range expected {
		assert.Equal(t, exp, k)
		if i < len(expected)-1 {
			k, _, ok = sm.next(k)
			assert.True(t, ok)
		}
	}

	// Backward traversal
	for i := len(expected) - 1; i >= 0; i-- {
		assert.Equal(t, expected[i], k)
		if i > 0 {
			k, _, ok = sm.prev(k)
			assert.True(t, ok)
		}
	}
}

// =============================================================================
// CONCURRENT TESTS
// =============================================================================

func TestLinkedMap_Concurrent_Reads(t *testing.T) {
	lm := newLinkedMap[string, int]()
	keys := make([]string, 100)
	for i := 0; i < 100; i++ {
		key := "key" + strconv.Itoa(i)
		keys[i] = key
		lm.put(key, i)
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				key := keys[j]
				_, _ = lm.get(key)
				_ = lm.contains(key)
				_ = lm.size()
				_, _, _ = lm.next(key)
				_, _, _ = lm.prev(key)
				_, _, _ = lm.first()
			}
		}()
	}

	wg.Wait()
	assert.Equal(t, 100, lm.size())
}

func TestLinkedMap_Concurrent_Writes(t *testing.T) {
	lm := newLinkedMap[string, int]()
	var wg sync.WaitGroup

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			baseKey := "goroutine" + strconv.Itoa(id) + "_"
			for j := 0; j < 20; j++ {
				key := baseKey + strconv.Itoa(j)
				lm.put(key, id*1000+j)
			}
		}(i)
	}

	wg.Wait()
	assert.Equal(t, 100, lm.size())
}

func TestLinkedMap_Concurrent_Mixed(t *testing.T) {
	lm := newLinkedMap[string, int]()
	keys := make([]string, 50)
	for i := 0; i < 50; i++ {
		key := "key" + strconv.Itoa(i)
		keys[i] = key
		lm.put(key, i)
	}

	var wg sync.WaitGroup

	// Readers
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				key := keys[j%50]
				_, _ = lm.get(key)
				_ = lm.contains(key)
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
				lm.put(key, id*1000+j)
				if j%5 == 0 {
					time.Sleep(time.Microsecond)
				}
			}
		}(i)
	}

	wg.Wait()
	assert.True(t, lm.size() >= 50)
	assert.True(t, lm.size() <= 110)
}

func TestLinkedMap_Concurrent_PutOrdered(t *testing.T) {
	sm := newLinkedMap[int, string]()
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				val := base*100 + j
				sm.putOrdered(val, "value")
			}
		}(i)
	}

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if j%2 == 0 {
					sm.get(j)
				} else {
					sm.remove(j)
				}
			}
		}()
	}

	wg.Wait()
}