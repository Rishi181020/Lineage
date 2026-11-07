const test = require("node:test");
const assert = require("node:assert/strict");
const { orderTotal } = require("../src/total");

test("totals an order payload", () => {
  assert.equal(orderTotal({ items: [{ price: 12.5, qty: 2 }] }), 25);
});
