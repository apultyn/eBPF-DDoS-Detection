package blocklist

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestMergeBlockEntry(t *testing.T) {
	last, drops := mergeBlockEntry([]blockEntry{{100, 3}, {0, 0}, {250, 7}, {90, 1}})
	if last != 250 || drops != 11 {
		t.Errorf("got last seen %d, %d drops; want 250, 11", last, drops)
	}
}

func TestSumTotals(t *testing.T) {
	got := sumTotals([]blockedTotals{{10, 1000}, {0, 0}, {5, 300}})
	if want := (Totals{Packets: 15, Bytes: 1300}); got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

// TestMirrorsC checks the names and size this package relies on against
// blocklist.c, since a mismatch would only show up on a live node.
func TestMirrorsC(t *testing.T) {
	src, err := os.ReadFile("blocklist.c")
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		fmt.Sprintf("#define BLOCKLIST_SIZE %d ", Size),
		fmt.Sprintf("} %s SEC(\".maps\");", mapName),
		fmt.Sprintf("} %s SEC(\".maps\");", statsName),
	} {
		if !strings.Contains(string(src), want) {
			t.Errorf("blocklist.c does not contain %q", want)
		}
	}
}
