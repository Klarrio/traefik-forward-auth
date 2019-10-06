package ttlmap

import (
	"testing"
	"time"
)

func TestAddGetRemove(t *testing.T) {
	key := "string-key"
	value := "value to lookup"
	m, _ := New()
	m.Add(key, value)
	item, existed := m.Get(key)
	if !existed {
		t.Fatal("Expected item", key, "but it was not found")
	}
	if item.Value().(string) != value {
		t.Fatal("Invalid value for", key, "{expected:", value, ", received:", item.Value(), "}")
	}
	_, wasRemoved := m.Remove(key)
	if !wasRemoved {
		t.Fatal("Expected", key, " to be removed")
	}
	if _, existed := m.Get(key); existed {
		t.Fatal("Expected item", key, "to not exist in the map but it was found")
	}

	if _, existed := m.Get(1); existed {
		t.Fatal("Expected item", key, "to not exist in the map but it was found")
	}
}

func TestExpire(t *testing.T) {
	key := "string-key"
	value := "value to lookup"
	m, _ := New()
	m.AddWithTTL(key, value, time.Duration(time.Millisecond*300))
	item, existed := m.Get(key)
	if !existed {
		t.Fatal("Expected item", key, "but it was not found")
	}
	if item.Value().(string) != value {
		t.Fatal("Invalid value for", key, "{expected:", value, ", received:", item.Value(), "}")
	}

	<-time.After(time.Duration(time.Millisecond * 500))

	if _, existed := m.Get(key); existed {
		t.Fatal("Expected item", key, "to not exist in the map but it was found")
	}
}

func TestExpireExtend(t *testing.T) {
	key := "string-key"
	value := "value to lookup"
	m, _ := New()
	m.AddWithTTL(key, value, time.Duration(time.Millisecond*300))
	item, existed := m.Get(key)
	if !existed {
		t.Fatal("Expected item", key, "but it was not found")
	}
	if item.Value().(string) != value {
		t.Fatal("Invalid value for", key, "{expected:", value, ", received:", item.Value(), "}")
	}
	m.AddWithTTL(key, value, time.Duration(time.Millisecond*2000))

	<-time.After(time.Duration(time.Millisecond * 1000))

	if _, existed := m.Get(key); !existed {
		t.Fatal("Expected item", key, "to still exist in the map but it was not found")
	}

	<-time.After(time.Duration(time.Millisecond * 2500))

	if _, existed := m.Get(key); existed {
		t.Fatal("Expected item", key, "to not exist anymore in the map but it was found")
	}
}
