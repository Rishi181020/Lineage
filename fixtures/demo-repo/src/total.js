function orderTotal(order) {
  // Bug: production payloads use `qty`, so this produces NaN.
  return order.items.reduce((sum, item) => sum + item.price * item.quantity, 0);
}

module.exports = { orderTotal };
