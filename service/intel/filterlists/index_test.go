package filterlists

import (
	"reflect"
	"testing"
)

const (
	catTRAC   = "TRAC"
	catTRACAD = "TRAC-AD"
	catMAL    = "MAL"
	catLoopA  = "LOOP-A"
	catLoopB  = "LOOP-B"
	srcAA     = "AA-AD"
	srcDM     = "DM-AD"
	srcUHB    = "UHB"
	srcX      = "X"
)

func TestWithCategories(t *testing.T) {
	t.Parallel()
	index := &ListIndexFile{
		Categories: []Category{
			{ID: catTRAC},
			{ID: catTRACAD, Parent: catTRAC},
			{ID: catMAL},
			// A loop must not hang.
			{ID: catLoopA, Parent: catLoopB},
			{ID: catLoopB, Parent: catLoopA},
		},
		Sources: []Source{
			{ID: srcAA, Category: catTRACAD},
			{ID: srcDM, Category: catTRAC},
			{ID: srcUHB, Category: catMAL},
			{ID: srcX, Category: catLoopA},
		},
	}
	for _, c := range []struct {
		ids, want []string
	}{
		{[]string{srcAA, srcDM}, []string{srcAA, srcDM, catTRAC, catTRACAD}},
		{[]string{srcUHB}, []string{catMAL, srcUHB}},
		{[]string{"unknown"}, []string{"unknown"}},
		{[]string{srcX}, []string{catLoopA, catLoopB, srcX}},
	} {
		if got := index.withCategories(c.ids); !reflect.DeepEqual(got, c.want) {
			t.Errorf("withCategories(%v) = %v, want %v", c.ids, got, c.want)
		}
	}
}
