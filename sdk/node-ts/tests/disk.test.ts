import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "vitest";
import { Disk } from "../src/index.js";

test("offline disk growth preserves source identity and refuses clobber", async () => {
  const directory = mkdtempSync(join(tmpdir(), "msb-disk-"));
  try {
    const source = join(directory, "source.ext4");
    const destination = join(directory, "next.ext4");
    const created = await Disk.create(source, 128n * 1024n * 1024n);
    const grown = await Disk.growCopy(source, destination, 256n * 1024n * 1024n);
    expect(grown.uuid).toBe(created.uuid);
    expect(grown.capacityBytes).toBe(256n * 1024n * 1024n);
    expect((await Disk.inspect(source)).capacityBytes).toBe(created.capacityBytes);
    await expect(Disk.growCopy(source, destination, 512n * 1024n * 1024n)).rejects.toThrow();
    await expect(Disk.create(join(directory, "negative"), -1n)).rejects.toThrow();
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
