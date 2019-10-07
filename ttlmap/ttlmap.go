package ttlmap

import (
	"os"
	"time"
)

// TTLMap represents a map with key expiry.
type TTLMap interface {
	Add(key interface{}, value interface{})
	AddWithTTL(key interface{}, value interface{}, ttl time.Duration)
	Get(key interface{}) (Item, bool)
	Remove(key interface{}) (Item, bool)
}

// Item represents a map item for the TTL map.
type Item interface {
	Value() interface{}
	ExpiresAt() time.Time
}

type entry struct {
	key       interface{}
	value     interface{}
	expiresAt time.Time
}

func (e *entry) Value() interface{} {
	return e.value
}

func (e *entry) ExpiresAt() time.Time {
	return e.expiresAt
}

func (e *entry) expire(whenTs time.Time, removeF func()) {
	go func() {
		<-time.After(e.expiresAt.Sub(time.Now()))
		if e.expiresAt.Equal(whenTs) {
			removeF()
		}
	}()
}

func (e *entry) update(value interface{}, expiresAt time.Time) {
	e.value = value
	e.expiresAt = expiresAt
}

type opAdd struct {
	key       interface{}
	value     interface{}
	expiresAt time.Time
	chanAdded chan *opFetchResult
}

type opFetchResult struct {
	item    Item
	existed bool
}

type opGet struct {
	key        interface{}
	chanResult chan *opFetchResult
}

type opRemove struct {
	key          interface{}
	chanResponse chan *opFetchResult
}

type ttlMap struct {
	defaultTTL time.Duration
	chanOp     chan interface{}
	contents   map[interface{}]*entry
}

// New creates a new TTLMap with the default TTL.
// The default TTL is 60 seconds or a value defined using TTL_MAP_DEFAULT_TTL environment variable.
// The value of the TTL_MAP_DEFAULT_TTL environment variable has to be a valid golang duration string.
func New() (TTLMap, error) {
	defaultTTL := time.Duration(time.Second * 60)
	if val, ok := os.LookupEnv("TTL_MAP_DEFAULT_TTL"); ok {
		d, err := time.ParseDuration(val)
		if err != nil {
			return nil, err
		}
		defaultTTL = d
	}
	return NewWithTTL(defaultTTL), nil
}

// NewWithTTL creates a new TTLMap with the specified default TTL duration.
func NewWithTTL(ttl time.Duration) TTLMap {
	return &ttlMap{
		defaultTTL: ttl,
		chanOp:     make(chan interface{}),
		contents:   map[interface{}]*entry{},
	}
}

// Add adds a value at a key with the default ttl.
func (m *ttlMap) Add(key interface{}, value interface{}) {
	m.AddWithTTL(key, value, m.defaultTTL)
}

// AddWithTTL adds a value at a key with the defined ttl.
func (m *ttlMap) AddWithTTL(key interface{}, value interface{}, ttl time.Duration) {
	op := &opAdd{
		key:       key,
		value:     value,
		expiresAt: time.Now().Add(ttl),
		chanAdded: make(chan *opFetchResult, 1),
	}
	go func() {
		m.processOnce()
		m.chanOp <- op
	}()
	<-op.chanAdded
	return
}

// Get fetches the item for the key. The result is a valid item when the boolean is true.
func (m *ttlMap) Get(key interface{}) (Item, bool) {
	op := &opGet{
		key:        key,
		chanResult: make(chan *opFetchResult, 1),
	}
	go func() {
		m.processOnce()
		m.chanOp <- op
	}()
	r := <-op.chanResult
	return r.item, r.existed
}

// Remove removes the key from the map.
// The boolean value indicates if the key was removed.
// If the key was removed, the removed item is returned to the caller.
func (m *ttlMap) Remove(key interface{}) (Item, bool) {
	op := &opRemove{
		key:          key,
		chanResponse: make(chan *opFetchResult, 1),
	}
	go func() {
		m.processOnce()
		m.chanOp <- op
	}()
	r := <-op.chanResponse
	return r.item, r.existed
}

func (m *ttlMap) processOnce() {
	go func() {
		op := <-m.chanOp
		switch top := op.(type) {
		case *opAdd:
			var item *entry
			var existed bool
			if e, ok := m.contents[top.key]; ok {
				item = e
				existed = true
				item.update(top.value, top.expiresAt)
				m.contents[top.key].expire(item.expiresAt, func() {
					m.Remove(top.key)
				})
			} else {
				newItem := &entry{
					key:       top.key,
					value:     top.value,
					expiresAt: top.expiresAt,
				}
				m.contents[top.key] = newItem
				m.contents[top.key].expire(newItem.expiresAt, func() {
					m.Remove(top.key)
				})
			}
			top.chanAdded <- &opFetchResult{
				item:    item,
				existed: existed,
			}
		case *opGet:
			if entry, ok := m.contents[top.key]; ok {
				top.chanResult <- &opFetchResult{
					item:    entry,
					existed: true,
				}
			} else {
				top.chanResult <- &opFetchResult{
					item:    nil,
					existed: false,
				}
			}
		case *opRemove:
			if entry, ok := m.contents[top.key]; ok {
				delete(m.contents, top.key)
				top.chanResponse <- &opFetchResult{
					item:    entry,
					existed: true,
				}
			} else {
				top.chanResponse <- &opFetchResult{
					item:    nil,
					existed: false,
				}
			}
		}
	}()
}
