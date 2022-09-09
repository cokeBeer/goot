package queue

import (
	"sync"

	"github.com/cokeBeer/goot/pkg/dataflow/util/entry"
)

// Queue represents a Queue
type Queue struct {
	queue []*entry.Entry
	len   int
	lock  *sync.Mutex // 后面可能会加锁
}

// New create a Queue
func New() *Queue {
	queue := new(Queue)
	queue.queue = make([]*entry.Entry, 0)
	queue.len = 0
	queue.lock = new(sync.Mutex)

	return queue
}

// Len returns the length of the Queue
func (q *Queue) Len() int {

	return q.len
}

func (q *Queue) isEmpty() bool {

	return q.len == 0
}

// Poll pops and returns the first entry in the Queue
func (q *Queue) Poll() *entry.Entry {
	if q.isEmpty() {

		return nil
	}
	el := q.queue[0]
	q.queue = q.queue[1:]
	q.len--

	return el
}

// Add adds an entry at last of the Queue
func (q *Queue) Add(el *entry.Entry) {
	q.queue = append(q.queue, el)
	q.len++
}

// Peek returns the last entry in Queue
func (q *Queue) Peek() *entry.Entry {
	if q.isEmpty() {

		return nil
	}

	return q.queue[0]
}

// Of creates a Queue from a slice of pointer to Entry
func Of(universe *[]*entry.Entry) *Queue {
	queue := New()
	for i, e := range *universe {
		e.Number = i
		queue.Add(e)
	}

	return queue
}
