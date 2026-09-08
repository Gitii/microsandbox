import { decode } from "cbor-x";
import { expect, test } from "vitest";

import { encodeEnvelope, PROTOCOL_VERSION, typedMessage } from "../src/message.js";

test("TCP byte credit is a nonterminal generation-7 message", () => {
  const message = typedMessage("core.tcp.credit", { bytes: 16384 });
  const frame = encodeEnvelope(message);
  expect(PROTOCOL_VERSION).toBe(7);
  expect(frame.flags).toBe(0);
  const envelope = decode(frame.body);
  expect(envelope.t).toBe("core.tcp.credit");
  expect(decode(envelope.p)).toEqual({ bytes: 16384 });
  expect(() => encodeEnvelope(message, 7, 6)).toThrow("needs protocol generation 7");
});
