// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
package nonblocking

import (
	"errors"
	"sync"
)

// EvictCallback is used to get a callback when a cache entry is evicted
type EvictCallback[K comparable, V any] func(key K, value V)

// LRU implements a non-thread safe fixed size LRU cache
type LRU[K comparable, V any] struct {
	itemsLock     sync.RWMutex
	evictListLock sync.RWMutex
	size          int
	evictList     *lruList[K, V]
	items         map[K]*entry[K, V]
	onEvict       EvictCallback[K, V]
	getChan       chan *entry[K, V]
}

// NewLRU constructs an LRU of the given size
func NewLRU[K comparable, V any](size int, onEvict EvictCallback[K, V]) (*LRU[K, V], error) {
	if size <= 0 {
		return nil, errors.New("must provide a positive size")
	}
	// Initialize the channel buffer size as being 10% of the cache size.
	chanSize := max(size/10, 1)

	c := &LRU[K, V]{
		size:      size,
		evictList: newList[K, V](),
		items:     make(map[K]*entry[K, V], size),
		onEvict:   onEvict,
		getChan:   make(chan *entry[K, V], chanSize),
	}
	// Spin off separate go-routine to handle evict list operations.
	go c.handleGetRequests()
	return c, nil
}

// Add adds a value to the cache. Returns true if an eviction occurred.
func (c *LRU[K, V]) Add(key K, value V) (evicted bool) {
	// Check for existing item
	c.itemsLock.RLock()
	ent, ok := c.items[key]
	c.itemsLock.RUnlock()

	if ok {
		// Move it to front and update value
		c.evictListLock.Lock()
		c.evictList.moveToFront(ent)
		c.evictListLock.Unlock()
		ent.value = value
		return false
	}

	// Add new item
	c.evictListLock.Lock()
	newEnt := c.evictList.pushFront(key, value)
	needEvict := c.evictList.length() > c.size
	c.evictListLock.Unlock()

	c.itemsLock.Lock()
	c.items[key] = newEnt
	c.itemsLock.Unlock()

	// If eviction needed, remove oldest (handles list+map+callback)
	if needEvict {
		c.removeOldest()
		return true
	}
	return false
}

// Get looks up a key's value from the cache.
func (c *LRU[K, V]) Get(key K) (value V, ok bool) {
	c.itemsLock.RLock()
	ent, ok := c.items[key]
	c.itemsLock.RUnlock()
	if !ok {
		var zero V
		return zero, false
	}

	// Non-blocking notify to move element to front.
	// If channel is full, skip the notification (the element will still be present;
	// recency might not be updated immediately).
	select {
	case c.getChan <- ent:
	default:
	}
	return ent.value, true
}

// Len returns the number of items in the cache.
func (c *LRU[K, V]) Len() int {
	c.evictListLock.RLock()
	l := c.evictList.length()
	c.evictListLock.RUnlock()
	return l
}

// Resize changes the cache size.
// Returns the number of evicted elements.
func (c *LRU[K, V]) Resize(size int) (evicted int) {
	if size < 0 {
		return 0
	}

	for c.Len() > size {
		c.removeOldest()
		evicted++
	}
	c.size = size
	return evicted
}

// removeOldest removes the oldest item from the cache.
func (c *LRU[K, V]) removeOldest() {
	c.evictListLock.RLock()
	ent := c.evictList.back()
	c.evictListLock.RUnlock()
	if ent != nil {
		c.removeElement(ent)
	}
}

// removeElement is used to remove a given list element from the cache
func (c *LRU[K, V]) removeElement(e *entry[K, V]) {
	c.evictListLock.Lock()
	c.evictList.remove(e)
	c.evictListLock.Unlock()

	c.itemsLock.Lock()
	delete(c.items, e.key)
	c.itemsLock.Unlock()
	if c.onEvict != nil {
		c.onEvict(e.key, e.value)
	}
}

func (c *LRU[K, V]) handleGetRequests() {
	for ent := range c.getChan {
		// Move the node to front; if the entry is already removed from the list,
		// moveToFront should be a no-op or safe (depends on implementation).
		c.evictListLock.Lock()
		c.evictList.moveToFront(ent)
		c.evictListLock.Unlock()
	}
}
