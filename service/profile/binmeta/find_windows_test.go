package binmeta

import (
	"context"
	"os"
	"testing"
)

func TestFindIcon(t *testing.T) {
	if testing.Short() {
		t.Skip("test meant for compiling and running on desktop")
	}
	t.Parallel()

	binName := os.Args[len(os.Args)-1]
	t.Logf("getting name and icon for %s", binName)
	png, name, err := getIconAndNamefromRSS(context.Background(), binName)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("name: %s", name)
	err = os.WriteFile("icon.png", png, 0o0600)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGetIconAndNameMissingBinary(t *testing.T) {
	t.Parallel()

	icon, name, err := GetIconAndName(context.Background(), `C:\does\not\exist\tool.exe`, "")
	if err != nil {
		t.Fatalf("missing binary should not be an error: %s", err)
	}
	if icon != nil {
		t.Errorf("missing binary should have no icon, got %+v", icon)
	}
	if name == "" {
		t.Error("name should be generated from the path")
	}
}
