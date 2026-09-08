import { decode } from "cbor-x";
import { readFileSync } from "node:fs";
import { expect, test } from "vitest";

import { encodeEnvelope, PROTOCOL_VERSION, typedMessage, minProtocolVersion, type MessageType } from "../src/message.js";

test("TCP byte credit is a nonterminal generation-7 message", () => {
  const message = typedMessage("core.tcp.credit", { bytes: 16384 });
  const frame = encodeEnvelope(message);
  expect(PROTOCOL_VERSION).toBe(7);
  expect(frame.flags).toBe(0);
  const envelope = decode(frame.body);
  expect(envelope.t).toBe("core.tcp.credit");
  expect(decode(envelope.p)).toEqual({ bytes: 16384 });
  expect(() => encodeEnvelope(message, 7, 6)).toThrow("needs protocol generation 7");
  expect(() => encodeEnvelope(typedMessage("core.tcp.connect", { host: "127.0.0.1", port: 80 }), 7, 6)).toThrow("needs protocol generation 7");
});

test("TypeScript generations match the current Rust wire snapshot", () => {
  const schema: { protocol_version: number; message_types: { wire: MessageType; introduced_in: number }[] } = JSON.parse(
    readFileSync(new URL("../../../../crates/protocol/schema/gen-7.json", import.meta.url), "utf8"),
  );
  expect(schema.protocol_version).toBe(PROTOCOL_VERSION);
  for (const message of schema.message_types) {
    expect(minProtocolVersion(message.wire), message.wire).toBe(message.introduced_in);
  }
});
