const jwt     = require("jsonwebtoken");
const express = require("express");
const mysql   = require("mysql2");
const cors    = require("cors");
const path    = require("path");

const SECRET = "warehouse_secret";

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const db = mysql.createConnection({
  host:     "localhost",
  user:     "root",
  password: "Ast@1506",
  database: "warehouse"
});

db.connect(err => {
  if (err) console.log("DB error:", err);
  else     console.log("MySQL Connected");
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

// Run a query wrapped in a Promise
function query(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.query(sql, params, (err, result) => {
      if (err) reject(err);
      else     resolve(result);
    });
  });
}

// ─── Auth Middleware ──────────────────────────────────────────────────────────

function authenticate(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });
  jwt.verify(token, SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: "Invalid or expired token" });
    req.user = decoded;
    next();
  });
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin")
    return res.status(403).json({ error: "Admin access required" });
  next();
}

const auth = [authenticate, adminOnly];

// ─── Auth Routes ──────────────────────────────────────────────────────────────

app.get("/", (req, res) => res.send("Warehouse Backend Running"));

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: "Username and password required" });
  try {
    const result = await query("SELECT * FROM users WHERE username = ?", [username]);
    if (!result.length) return res.status(401).json({ error: "Invalid credentials" });
    const user = result[0];
    if (password !== user.password) return res.status(401).json({ error: "Invalid credentials" });
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      SECRET, { expiresIn: "8h" }
    );
    res.json({ token, role: user.role, username: user.username });
  } catch { res.status(500).json({ error: "DB error" }); }
});

app.get("/verify", authenticate, (req, res) => {
  res.json({ valid: true, user: req.user });
});

// ─── Categories ───────────────────────────────────────────────────────────────

app.get("/categories", ...auth, async (req, res) => {
  try {
    const rows = await query("SELECT * FROM categories ORDER BY name ASC");
    res.json(rows);
  } catch { res.status(500).json({ error: "DB error" }); }
});

app.post("/categories", ...auth, async (req, res) => {
  const { name, description } = req.body;
  if (!name) return res.status(400).json({ error: "Category name is required" });
  try {
    const result = await query(
      "INSERT INTO categories (name, description) VALUES (?, ?)",
      [name, description || null]
    );
    res.json({ id: result.insertId, message: "Category added" });
  } catch { res.status(500).json({ error: "DB error" }); }
});

app.delete("/categories/:id", ...auth, async (req, res) => {
  try {
    // Check if any product uses this category
    const used = await query("SELECT id FROM products WHERE category_id = ?", [req.params.id]);
    if (used.length)
      return res.status(400).json({ error: `Cannot delete — ${used.length} product(s) use this category` });
    await query("DELETE FROM categories WHERE id = ?", [req.params.id]);
    res.json({ message: "Category deleted" });
  } catch { res.status(500).json({ error: "DB error" }); }
});

// ─── Products ─────────────────────────────────────────────────────────────────

app.get("/products", ...auth, async (req, res) => {
  try {
    const rows = await query(`
      SELECT p.*, c.name AS category_name
      FROM products p
      LEFT JOIN categories c ON p.category_id = c.id
      ORDER BY p.id DESC
    `);
    res.json(rows);
  } catch { res.status(500).json({ error: "DB error" }); }
});

app.post("/products", ...auth, async (req, res) => {
  const { name, quantity, price, category_id } = req.body;
  if (!name || quantity == null || price == null)
    return res.status(400).json({ error: "name, quantity and price are required" });
  try {
    const result = await query(
      "INSERT INTO products (name, quantity, price, category_id) VALUES (?, ?, ?, ?)",
      [name, quantity, price, category_id || null]
    );
    res.json({ id: result.insertId, message: "Product added" });
  } catch { res.status(500).json({ error: "DB error" }); }
});

app.put("/products/:id", ...auth, async (req, res) => {
  const { name, quantity, price, category_id } = req.body;
  if (!name || quantity == null || price == null)
    return res.status(400).json({ error: "name, quantity and price are required" });
  try {
    await query(
      "UPDATE products SET name=?, quantity=?, price=?, category_id=? WHERE id=?",
      [name, quantity, price, category_id || null, req.params.id]
    );
    res.json({ message: "Product updated" });
  } catch { res.status(500).json({ error: "DB error" }); }
});

app.delete("/products/:id", ...auth, async (req, res) => {
  try {
    await query("DELETE FROM products WHERE id = ?", [req.params.id]);
    res.json({ message: "Product deleted" });
  } catch { res.status(500).json({ error: "DB error" }); }
});

// ─── Suppliers ────────────────────────────────────────────────────────────────

app.get("/suppliers", ...auth, async (req, res) => {
  try {
    res.json(await query("SELECT * FROM suppliers ORDER BY id DESC"));
  } catch { res.status(500).json({ error: "DB error" }); }
});

app.get("/suppliers/:id", ...auth, async (req, res) => {
  try {
    const rows = await query("SELECT * FROM suppliers WHERE id = ?", [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: "Supplier not found" });
    res.json(rows[0]);
  } catch { res.status(500).json({ error: "DB error" }); }
});

app.post("/suppliers", ...auth, async (req, res) => {
  const { name, contact_person, phone, email, address } = req.body;
  if (!name) return res.status(400).json({ error: "Supplier name is required" });
  try {
    const result = await query(
      "INSERT INTO suppliers (name, contact_person, phone, email, address) VALUES (?, ?, ?, ?, ?)",
      [name, contact_person || null, phone || null, email || null, address || null]
    );
    res.json({ id: result.insertId, message: "Supplier added" });
  } catch { res.status(500).json({ error: "DB error" }); }
});

app.put("/suppliers/:id", ...auth, async (req, res) => {
  const { name, contact_person, phone, email, address } = req.body;
  if (!name) return res.status(400).json({ error: "Supplier name is required" });
  try {
    await query(
      "UPDATE suppliers SET name=?, contact_person=?, phone=?, email=?, address=? WHERE id=?",
      [name, contact_person || null, phone || null, email || null, address || null, req.params.id]
    );
    res.json({ message: "Supplier updated" });
  } catch { res.status(500).json({ error: "DB error" }); }
});

app.delete("/suppliers/:id", ...auth, async (req, res) => {
  try {
    const orders = await query("SELECT id FROM orders WHERE supplier_id = ?", [req.params.id]);
    if (orders.length)
      return res.status(400).json({ error: "Cannot delete supplier with existing orders" });
    await query("DELETE FROM suppliers WHERE id = ?", [req.params.id]);
    res.json({ message: "Supplier deleted" });
  } catch { res.status(500).json({ error: "DB error" }); }
});

// ─── Orders ───────────────────────────────────────────────────────────────────

app.get("/orders", ...auth, async (req, res) => {
  try {
    const rows = await query(`
      SELECT o.id, o.order_date, o.status, o.total_amount,
             s.name AS supplier_name, s.id AS supplier_id
      FROM orders o
      JOIN suppliers s ON o.supplier_id = s.id
      ORDER BY o.id DESC
    `);
    res.json(rows);
  } catch { res.status(500).json({ error: "DB error" }); }
});

app.get("/orders/:id", ...auth, async (req, res) => {
  try {
    const orders = await query(`
      SELECT o.id, o.order_date, o.status, o.total_amount,
             s.name AS supplier_name, s.id AS supplier_id
      FROM orders o JOIN suppliers s ON o.supplier_id = s.id
      WHERE o.id = ?
    `, [req.params.id]);
    if (!orders.length) return res.status(404).json({ error: "Order not found" });

    const items = await query(`
      SELECT oi.id, oi.quantity, oi.unit_price,
             p.name AS product_name, p.id AS product_id
      FROM order_items oi JOIN products p ON oi.product_id = p.id
      WHERE oi.order_id = ?
    `, [req.params.id]);

    res.json({ ...orders[0], items });
  } catch { res.status(500).json({ error: "DB error" }); }
});

app.post("/orders", ...auth, async (req, res) => {
  const { supplier_id, items } = req.body;
  if (!supplier_id) return res.status(400).json({ error: "supplier_id is required" });
  if (!items || !items.length) return res.status(400).json({ error: "Order must have at least one item" });
  for (const item of items) {
    if (!item.product_id || !item.quantity || !item.unit_price)
      return res.status(400).json({ error: "Each item needs product_id, quantity, unit_price" });
  }
  const total_amount = items.reduce((s, i) => s + i.quantity * i.unit_price, 0);
  try {
    const order = await query(
      "INSERT INTO orders (supplier_id, total_amount, status) VALUES (?, ?, 'pending')",
      [supplier_id, total_amount]
    );
    const order_id = order.insertId;
    await query(
      "INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES ?",
      [items.map(i => [order_id, i.product_id, i.quantity, i.unit_price])]
    );
    res.json({ id: order_id, message: "Order created", total_amount });
  } catch { res.status(500).json({ error: "DB error" }); }
});

// ─── Order Status Update (with stock sync) ────────────────────────────────────

app.patch("/orders/:id/status", ...auth, async (req, res) => {
  const { status } = req.body;
  const allowed = ["pending", "received", "cancelled"];
  if (!allowed.includes(status))
    return res.status(400).json({ error: "Status must be: pending, received, or cancelled" });

  const orderId = Number(req.params.id);

  try {
    // Get current order status
    const orders = await query("SELECT status FROM orders WHERE id = ?", [orderId]);
    if (!orders.length) return res.status(404).json({ error: "Order not found" });

    const prevStatus = orders[0].status;

    // Nothing to do if status hasn't changed
    if (prevStatus === status)
      return res.json({ message: "Status unchanged" });

    // Get order items
    const items = await query(
      "SELECT product_id, quantity FROM order_items WHERE order_id = ?",
      [orderId]
    );

    // ── Case 1: Marking as RECEIVED ───────────────────────────────────────────
    // Increase stock for each item and log the movement
    if (status === "received" && prevStatus !== "received") {
      for (const item of items) {
        await query(
          "UPDATE products SET quantity = quantity + ? WHERE id = ?",
          [item.quantity, item.product_id]
        );
        await query(
          `INSERT INTO stock_movements
            (product_id, type, quantity, reason, reference_id, reference_type)
           VALUES (?, 'in', ?, ?, ?, 'order')`,
          [item.product_id, item.quantity, `Order #${orderId} received`, orderId]
        );
      }
    }

    // ── Case 2: CANCELLING an already-received order ──────────────────────────
    // Reverse the stock and log the reversal
    if (status === "cancelled" && prevStatus === "received") {
      for (const item of items) {
        await query(
          "UPDATE products SET quantity = GREATEST(quantity - ?, 0) WHERE id = ?",
          [item.quantity, item.product_id]
        );
        await query(
          `INSERT INTO stock_movements
            (product_id, type, quantity, reason, reference_id, reference_type)
           VALUES (?, 'out', ?, ?, ?, 'order')`,
          [item.product_id, item.quantity, `Order #${orderId} cancelled — stock reversed`, orderId]
        );
      }
    }

    // Update the order status
    await query("UPDATE orders SET status = ? WHERE id = ?", [status, orderId]);

    res.json({ message: `Order status updated to ${status}` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "DB error during status update" });
  }
});

app.delete("/orders/:id", ...auth, async (req, res) => {
  try {
    const result = await query("DELETE FROM orders WHERE id = ?", [req.params.id]);
    if (!result.affectedRows) return res.status(404).json({ error: "Order not found" });
    res.json({ message: "Order deleted" });
  } catch { res.status(500).json({ error: "DB error" }); }
});

// ─── Stock Movements ──────────────────────────────────────────────────────────

// Get all movements — optionally filter by product_id via ?product_id=X
app.get("/stock-movements", ...auth, async (req, res) => {
  try {
    const { product_id } = req.query;
    let sql = `
      SELECT sm.*, p.name AS product_name
      FROM stock_movements sm
      JOIN products p ON sm.product_id = p.id
    `;
    const params = [];
    if (product_id) {
      sql += " WHERE sm.product_id = ?";
      params.push(product_id);
    }
    sql += " ORDER BY sm.created_at DESC LIMIT 200";
    res.json(await query(sql, params));
  } catch { res.status(500).json({ error: "DB error" }); }
});

// Manual stock adjustment (e.g. damage, correction)
app.post("/stock-movements", ...auth, async (req, res) => {
  const { product_id, type, quantity, reason } = req.body;
  if (!product_id || !type || !quantity)
    return res.status(400).json({ error: "product_id, type and quantity are required" });
  if (!["in", "out"].includes(type))
    return res.status(400).json({ error: "type must be 'in' or 'out'" });
  try {
    // Check product exists
    const products = await query("SELECT id, quantity FROM products WHERE id = ?", [product_id]);
    if (!products.length) return res.status(404).json({ error: "Product not found" });

    const delta = type === "in" ? quantity : -quantity;
    const newQty = products[0].quantity + delta;
    if (newQty < 0)
      return res.status(400).json({ error: "Insufficient stock for this adjustment" });

    await query("UPDATE products SET quantity = ? WHERE id = ?", [newQty, product_id]);
    const result = await query(
      `INSERT INTO stock_movements (product_id, type, quantity, reason, reference_type)
       VALUES (?, ?, ?, ?, 'manual')`,
      [product_id, type, quantity, reason || "Manual adjustment"]
    );
    res.json({ id: result.insertId, message: "Stock adjusted", new_quantity: newQty });
  } catch { res.status(500).json({ error: "DB error" }); }
});

// ─── Start ────────────────────────────────────────────────────────────────────

app.listen(3000, () => console.log("Server started on port 3000"));