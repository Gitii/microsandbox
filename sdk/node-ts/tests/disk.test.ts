import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "vitest";
import { Disk } from "../src/index.js";

test("offline disk growth preserves source identity and refuses clobber", () => {
  const directory = mkdtempSync(join(tmpdir(), "msb-disk-"));
  try {
    const source = join(directory, "source.ext4");
    const destination = join(directory, "next.ext4");
    const created = Disk.create(source, 128n * 1024n * 1024n);
    const grown = Disk.growCopy(source, destination, 256n * 1024n * 1024n);
    expect(grown.uuid).toBe(created.uuid);
    expect(grown.capacityBytes).toBe(256n * 1024n * 1024n);
    expect(Disk.inspect(source).capacityBytes).toBe(created.capacityBytes);
    expect(() => Disk.growCopy(source, destination, 512n * 1024n * 1024n)).toThrow();
    expect(() => Disk.create(join(directory, "negative"), -1n)).toThrow();
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
