package main

import "sync"

type RuntimeClientAuth struct {
	mu  sync.RWMutex
	key string
}

func NewRuntimeClientAuth(key string) *RuntimeClientAuth {
	return &RuntimeClientAuth{key: key}
}

func (a *RuntimeClientAuth) Key() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.key
}

func (a *RuntimeClientAuth) Update(key string) {
	a.mu.Lock()
	a.key = key
	a.mu.Unlock()
}

func (a *RuntimeClientAuth) Valid(value string) bool {
	key := a.Key()
	return key != "" && constantTimeEqual(value, key)
}
