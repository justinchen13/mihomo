package main

import "sync"

// Eight workers exist only before GO. The measured path does not call this.
func setupWorkers(jobs []int, work func(int) error) error {
	q := make(chan int, len(jobs))
	for _, id := range jobs {
		q <- id
	}
	close(q)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var first error
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range q {
				mu.Lock()
				failed := first != nil
				mu.Unlock()
				if failed {
					continue
				}
				if err := work(id); err != nil {
					mu.Lock()
					if first == nil {
						first = err
					}
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	return first
}
