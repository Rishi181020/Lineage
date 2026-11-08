const { round2 } = require("orders-money");

function orderTotal(order) {
  // Bug: production payloads use `qty`, so this produces NaN.
  return round2(order.items.reduce((sum, item) => sum + item.price * item.quantity, 0));
}

module.exports = { orderTotal };
