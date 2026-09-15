package microsandbox

import (
	"encoding/json"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// DiskInfo is validated ext4 metadata, not a checksum of file payloads.
type DiskInfo struct {
	UUID           string  `json:"uuid"`
	CapacityBytes  uint64  `json:"capacity_bytes"`
	FileBytes      uint64  `json:"file_bytes"`
	AllocatedBytes *uint64 `json:"allocated_bytes"`
	NeedsRecovery  bool    `json:"needs_recovery"`
}

// CreateDisk synchronously publishes a sparse ext4 image at an exclusive path.
// Sizes are bytes. Hold an exclusive lifecycle lock through manifest adoption.
func CreateDisk(path string, sizeBytes uint64) (*DiskInfo, error) {
	return diskOperation("create", "", path, sizeBytes)
}

// InspectDisk reads metadata without modifying a stopped, detached image.
func InspectDisk(path string) (*DiskInfo, error) {
	return diskOperation("inspect", path, "", 0)
}

// GrowDiskCopy publishes a verified larger copy without changing source.
// Stop/detach all users and hold a lifecycle lock through manifest adoption.
// The caller removes the retained source only after adopting the replacement.
func GrowDiskCopy(source, destination string, sizeBytes uint64) (*DiskInfo, error) {
	return diskOperation("grow_copy", source, destination, sizeBytes)
}

func diskOperation(operation, source, destination string, sizeBytes uint64) (*DiskInfo, error) {
	raw, err := ffi.DiskOperation(operation, source, destination, sizeBytes)
	if err != nil {
		return nil, wrapFFI(err)
	}
	var info DiskInfo
	if err := json.Unmarshal([]byte(raw), &info); err != nil {
		return nil, err
	}
	return &info, nil
}
