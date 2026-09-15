import { napi } from "./internal/napi.js";

/** Validated ext4 metadata, not a checksum of file payloads. */
export interface DiskInfo {
  uuid: string;
  capacityBytes: bigint;
  fileBytes: bigint;
  allocatedBytes?: bigint;
  needsRecovery: boolean;
}

/** Local operations, run off the JS thread. Stop/detach all users and hold a
 * lifecycle lock through maintenance and manifest adoption. Root snapshots
 * exclude extra disks.
 */
export class Disk {
  /** Create a sparse ext4 image without replacing an existing destination. */
  static create(path: string, sizeBytes: bigint): Promise<DiskInfo> {
    return napi.diskCreate(path, sizeBytes);
  }

  /** Inspect without modifying the image. */
  static inspect(path: string): Promise<DiskInfo> {
    return napi.diskInspect(path);
  }

  /** Publish a verified larger copy; source remains unchanged even on failure. */
  static growCopy(source: string, destination: string, sizeBytes: bigint): Promise<DiskInfo> {
    return napi.diskGrowCopy(source, destination, sizeBytes);
  }
}
