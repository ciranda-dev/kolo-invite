package invite

import "time"

// bucket is a token bucket of size rate, refilled at rate tokens per minute.
type bucket struct {
	tokens float64
	last   int64 // Unix nanoseconds; 0 means full
}

func (b *bucket) refill(now int64, rate int) {
	if b.last == 0 {
		b.tokens = float64(rate)
	} else if now > b.last {
		b.tokens = min(float64(rate), b.tokens+float64(now-b.last)*float64(rate)/float64(time.Minute))
	}
	b.last = now
}

func (b *bucket) take(now int64, rate int) bool {
	b.refill(now, rate)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// full reports whether the bucket is back to its size, so forgetting it changes nothing.
func (b *bucket) full(now int64, rate int) bool {
	b.refill(now, rate)
	return b.tokens >= float64(rate)
}

// allowSourceLocked spends a token of source's bucket; a new source past MaxSources is refused unless a full
// bucket can be forgotten.
func (in *Inviter) allowSourceLocked(source string, now int64) bool {
	b := in.sources[source]
	if b == nil {
		if len(in.sources) >= in.opts.MaxSources {
			for s, o := range in.sources {
				if o.full(now, in.opts.SourceRate) {
					delete(in.sources, s)
				}
			}
			if len(in.sources) >= in.opts.MaxSources {
				return false
			}
		}
		b = &bucket{}
		in.sources[source] = b
	}
	return b.take(now, in.opts.SourceRate)
}
