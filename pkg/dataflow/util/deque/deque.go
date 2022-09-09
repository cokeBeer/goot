package deque

import (
	"sync"

	"github.com/cokeBeer/goot/pkg/dataflow/util/entry"
)

// Deque represents a deque of entry
type Deque struct {
	queue []*entry.Entry
	len   int
	lock  *sync.Mutex // may add lock later?
}

// New returns a Deque
func New() *Deque {
	deque := &Deque{}
	deque.queue = make([]*entry.Entry, 0)
	deque.len = 0
	deque.lock = new(sync.Mutex)

	return deque
}

// Len returns length of the Deque
func (d *Deque) Len() int {
	return d.len
}

func (d *Deque) isEmpty() bool {
	return d.len == 0
}

// PollFirst pops and returns the first entry in the Deque
func (d *Deque) PollFirst() *entry.Entry {
	el := d.queue[0]
	d.queue = d.queue[1:]
	d.len--
	return el
}

// PollLast pops and returns the last entry in the Deque
func (d *Deque) PollLast() *entry.Entry {
	el := d.queue[d.len-1]
	d.len--
	return el
}

// AddFirst adds an entry at first of the Deque
func (d *Deque) AddFirst(el *entry.Entry) {
	d.queue = append([]*entry.Entry{el}, d.queue...)
	d.len++
	return
}

// AddLast adds an entry at last of the Deque
func (d *Deque) AddLast(el *entry.Entry) {
	d.queue = append(d.queue[0:d.len], el)
	d.len++
	return
}
