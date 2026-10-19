package client

import (
	"context"
	"iter"
)

// Page is one page of a cursor-paginated list. Next is the cursor for the
// following page and is empty on the last page.
type Page[T any] struct {
	Items []T    `json:"items"`
	Next  string `json:"next,omitempty"`
}

// ListOptions paginate simple lists.
type ListOptions struct {
	// After is an exclusive cursor, normally a previous Page.Next.
	After string
	// Limit is the page size (server default if zero).
	Limit int
}

// paginate turns a page fetcher into an iterator that follows Next cursors.
// Iteration stops after the first error, which is yielded once.
func paginate[T any](ctx context.Context, after string, fetch func(ctx context.Context, after string) (Page[T], error)) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		for {
			p, err := fetch(ctx, after)
			if err != nil {
				var zero T
				yield(zero, err)
				return
			}
			for _, it := range p.Items {
				if !yield(it, nil) {
					return
				}
			}
			if p.Next == "" || p.Next == after {
				return
			}
			after = p.Next
		}
	}
}

// Collect drains an iterator into a slice, stopping at the first error.
func Collect[T any](seq iter.Seq2[T, error]) ([]T, error) {
	var out []T
	for v, err := range seq {
		if err != nil {
			return out, err
		}
		out = append(out, v)
	}
	return out, nil
}
