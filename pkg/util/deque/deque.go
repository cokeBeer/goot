package deque

import (
	"sync"

	"github.com/cokeBeer/goot/pkg/util/entry"
)

type Deque struct {
	queue []*entry.Entry
	len   int
	lock  *sync.Mutex // 后面可能会加锁
}

func New() *Deque {
	deque := &Deque{}
	deque.queue = make([]*entry.Entry, 0)
	deque.len = 0
	deque.lock = new(sync.Mutex)

	return deque
}

func (d *Deque) Len() int {
	return d.len
}

func (d *Deque) isEmpty() bool {
	return d.len == 0
}

func (d *Deque) PollFirst() *entry.Entry {
	el := d.queue[0]
	d.queue = d.queue[1:]
	d.len--
	return el
}

func (d *Deque) PollLast() *entry.Entry {
	el := d.queue[d.len-1]
	d.len--
	return el
}

func (d *Deque) AddFirst(el *entry.Entry) {
	d.queue = append([]*entry.Entry{el}, d.queue...)
	d.len++
	return
}

func (d *Deque) AddLast(el *entry.Entry) {
	d.queue = append(d.queue[0:d.len], el)
	d.len++
	return
}
