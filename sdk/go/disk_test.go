//go:build microsandbox_ffi_path

package microsandbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOfflineDiskCopy(t *testing.T) {
	dir := t.TempDir()
	source, destination := filepath.Join(dir, "source.ext4"), filepath.Join(dir, "next.ext4")
	created, err := Disk.Create(source, 128*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	grown, err := Disk.GrowCopy(source, destination, 256*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if grown.UUID != created.UUID || grown.CapacityBytes != 256*1024*1024 {
		t.Fatalf("unexpected replacement: %+v", grown)
	}
	old, err := Disk.Inspect(source)
	if err != nil {
		t.Fatal(err)
	}
	if old.CapacityBytes != created.CapacityBytes {
		t.Fatal("source capacity changed")
	}
	if _, err := Disk.GrowCopy(source, destination, 512*1024*1024); err == nil {
		t.Fatal("clobbered destination")
	}
	if _, err := Disk.GrowCopy(filepath.Join(dir, "missing"), filepath.Join(dir, "blank"), 256*1024*1024); err == nil {
		t.Fatal("accepted missing source")
	}
	if _, err := os.Stat(filepath.Join(dir, "blank")); !os.IsNotExist(err) {
		t.Fatal("published blank replacement")
	}
}
