// ─────────────────────────────────────────────────────────────────────────────
//  seed.js  —  Populates the warehouse DB with realistic synthetic order data
//  Run with:  node seed.js
// ─────────────────────────────────────────────────────────────────────────────

const mysql = require("mysql2/promise");

const DB = {
  host:     "localhost",
  user:     "root",
  password: "Ast@1506",
  database: "warehouse",
};

// ─── Seed Data Definitions ───────────────────────────────────────────────────

const CATEGORIES = [
  { name: "Electronics",    description: "Gadgets, devices and accessories" },
  { name: "Grocery",        description: "Food and daily essentials" },
  { name: "Stationery",     description: "Office and school supplies" },
  { name: "Clothing",       description: "Apparel and fashion items" },
  { name: "Home & Kitchen", description: "Household and kitchen products" },
  { name: "Health & Care",  description: "Medicines and personal care" },
];

// Each product has a `trend` that controls order frequency over time:
//   rising   → ordered more frequently towards recent weeks
//   falling  → ordered less frequently in recent weeks
//   seasonal → spikes every ~14 days
//   steady   → consistent demand throughout
const PRODUCTS = [
  // Electronics — trending up (new tech season)
  { name: "USB-C Charging Hub",       price: 1299,  cat: "Electronics",    trend: "rising",   baseQty: [5, 20]  },
  { name: "Wireless Earbuds",         price: 2499,  cat: "Electronics",    trend: "rising",   baseQty: [3, 12]  },
  { name: "HDMI 2.1 Cable",           price: 499,   cat: "Electronics",    trend: "steady",   baseQty: [10, 30] },
  { name: "Bluetooth Speaker",        price: 1799,  cat: "Electronics",    trend: "seasonal", baseQty: [4, 15]  },
  { name: "Laptop Stand",             price: 899,   cat: "Electronics",    trend: "rising",   baseQty: [5, 18]  },

  // Grocery — steady / falling (seasonal shift)
  { name: "Basmati Rice 5kg",         price: 420,   cat: "Grocery",        trend: "steady",   baseQty: [20, 80] },
  { name: "Sunflower Oil 1L",         price: 165,   cat: "Grocery",        trend: "falling",  baseQty: [15, 60] },
  { name: "Instant Noodles Pack",     price: 55,    cat: "Grocery",        trend: "steady",   baseQty: [30, 100]},
  { name: "Green Tea 100 bags",       price: 320,   cat: "Grocery",        trend: "rising",   baseQty: [10, 40] },
  { name: "Mixed Nuts 500g",          price: 650,   cat: "Grocery",        trend: "seasonal", baseQty: [8, 25]  },

  // Stationery — steady with slight seasonal spike
  { name: "A4 Paper Ream 500 sheets", price: 280,   cat: "Stationery",     trend: "steady",   baseQty: [15, 50] },
  { name: "Ball Pen Box (10 pcs)",    price: 120,   cat: "Stationery",     trend: "rising",   baseQty: [10, 40] },
  { name: "Sticky Notes Pack",        price: 95,    cat: "Stationery",     trend: "steady",   baseQty: [8, 30]  },
  { name: "Stapler Heavy Duty",       price: 350,   cat: "Stationery",     trend: "falling",  baseQty: [3, 10]  },

  // Clothing — seasonal spikes
  { name: "Cotton T-Shirt (Pack 3)",  price: 799,   cat: "Clothing",       trend: "seasonal", baseQty: [10, 35] },
  { name: "Formal Trouser",           price: 1299,  cat: "Clothing",       trend: "falling",  baseQty: [5, 15]  },
  { name: "Sports Socks (6 pairs)",   price: 349,   cat: "Clothing",       trend: "rising",   baseQty: [8, 28]  },

  // Home & Kitchen
  { name: "Stainless Steel Bottle",   price: 599,   cat: "Home & Kitchen", trend: "rising",   baseQty: [6, 22]  },
  { name: "Non-stick Frying Pan",     price: 1199,  cat: "Home & Kitchen", trend: "steady",   baseQty: [4, 14]  },
  { name: "Dish Soap 1L",             price: 140,   cat: "Home & Kitchen", trend: "steady",   baseQty: [20, 60] },

  // Health & Care
  { name: "Hand Sanitizer 500ml",     price: 180,   cat: "Health & Care",  trend: "falling",  baseQty: [15, 50] },
  { name: "Vitamin C Tablets 60pc",   price: 350,   cat: "Health & Care",  trend: "rising",   baseQty: [8, 25]  },
  { name: "Face Mask Box 50pc",       price: 299,   cat: "Health & Care",  trend: "falling",  baseQty: [10, 40] },
  { name: "Pain Relief Roll-on",      price: 220,   cat: "Health & Care",  trend: "steady",   baseQty: [6, 20]  },
];

const SUPPLIERS = [
  { name: "TechZone Distributors",  contact_person: "Arun Kumar",    phone: "9876543210", email: "arun@techzone.in",    address: "Chennai, TN" },
  { name: "FreshMart Wholesale",    contact_person: "Priya Nair",    phone: "9812345678", email: "priya@freshmart.in",  address: "Kochi, KL" },
  { name: "OfficeHub Supplies",     contact_person: "Ravi Menon",    phone: "9823456789", email: "ravi@officehub.in",   address: "Bangalore, KA" },
  { name: "FashionFirst Ltd",       contact_person: "Sneha Patel",   phone: "9834567890", email: "sneha@fashionfirst.in", address: "Surat, GJ" },
  { name: "HomeEssentials Co",      contact_person: "Manoj Sharma",  phone: "9845678901", email: "manoj@homeessentials.in", address: "Delhi, DL" },
  { name: "MedPlus Wholesale",      contact_person: "Divya Krishnan",phone: "9856789012", email: "divya@medplus.in",    address: "Hyderabad, TS" },
];

// Map category name → supplier index (0-based)
const CAT_SUPPLIER_MAP = {
  "Electronics":    0,
  "Grocery":        1,
  "Stationery":     2,
  "Clothing":       3,
  "Home & Kitchen": 4,
  "Health & Care":  5,
};

// ─── Utility Functions ───────────────────────────────────────────────────────

function randInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randChoice(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

// Generate a date string N days ago from today
function daysAgo(n) {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return d.toISOString().slice(0, 19).replace("T", " ");
}

// Determine if an order should be placed on a given day based on trend
// dayIndex: 0 = 60 days ago, 59 = today
function shouldOrder(trend, dayIndex, totalDays = 60) {
  const progress = dayIndex / totalDays; // 0.0 → 1.0
  let probability;
  switch (trend) {
    case "rising":
      // Low early, high recently  (0.2 → 0.8)
      probability = 0.2 + 0.6 * progress;
      break;
    case "falling":
      // High early, low recently  (0.8 → 0.2)
      probability = 0.8 - 0.6 * progress;
      break;
    case "seasonal":
      // Sinusoidal — peaks every ~14 days
      probability = 0.3 + 0.5 * Math.abs(Math.sin((dayIndex / 14) * Math.PI));
      break;
    case "steady":
    default:
      probability = 0.45 + (Math.random() * 0.1 - 0.05); // ~40-50% with noise
      break;
  }
  return Math.random() < probability;
}

// ─── Main Seed Function ──────────────────────────────────────────────────────

async function seed() {
  const conn = await mysql.createConnection(DB);
  console.log("✅  Connected to MySQL");

  try {
    // ── Step 1: Insert Categories ──────────────────────────────────────────────
    console.log("\n📂  Inserting categories...");
    const catIdMap = {};
    for (const cat of CATEGORIES) {
      const [existing] = await conn.execute(
        "SELECT id FROM categories WHERE name = ?", [cat.name]
      );
      if (existing.length) {
        catIdMap[cat.name] = existing[0].id;
        console.log(`   ⏭  Category already exists: ${cat.name}`);
      } else {
        const [result] = await conn.execute(
          "INSERT INTO categories (name, description) VALUES (?, ?)",
          [cat.name, cat.description]
        );
        catIdMap[cat.name] = result.insertId;
        console.log(`   ➕  Category added: ${cat.name} (id=${result.insertId})`);
      }
    }

    // ── Step 2: Insert Suppliers ───────────────────────────────────────────────
    console.log("\n🏭  Inserting suppliers...");
    const supplierIds = [];
    for (const sup of SUPPLIERS) {
      const [existing] = await conn.execute(
        "SELECT id FROM suppliers WHERE name = ?", [sup.name]
      );
      if (existing.length) {
        supplierIds.push(existing[0].id);
        console.log(`   ⏭  Supplier already exists: ${sup.name}`);
      } else {
        const [result] = await conn.execute(
          "INSERT INTO suppliers (name, contact_person, phone, email, address) VALUES (?, ?, ?, ?, ?)",
          [sup.name, sup.contact_person, sup.phone, sup.email, sup.address]
        );
        supplierIds.push(result.insertId);
        console.log(`   ➕  Supplier added: ${sup.name} (id=${result.insertId})`);
      }
    }

    // Build supplier name → DB id map
    const supNameToId = {};
    SUPPLIERS.forEach((s, i) => { supNameToId[s.name] = supplierIds[i]; });

    // ── Step 3: Insert Products ────────────────────────────────────────────────
    console.log("\n📦  Inserting products...");
    const productMap = {}; // name → { id, price, trend, baseQty, cat }
    for (const prod of PRODUCTS) {
      const catId = catIdMap[prod.cat];
      const [existing] = await conn.execute(
        "SELECT id FROM products WHERE name = ?", [prod.name]
      );
      if (existing.length) {
        productMap[prod.name] = { id: existing[0].id, ...prod };
        console.log(`   ⏭  Product already exists: ${prod.name}`);
      } else {
        const [result] = await conn.execute(
          "INSERT INTO products (name, quantity, price, category_id) VALUES (?, ?, ?, ?)",
          [prod.name, 0, prod.price, catId]
        );
        productMap[prod.name] = { id: result.insertId, ...prod };
        console.log(`   ➕  Product added: ${prod.name} (id=${result.insertId})`);
      }
    }

    // ── Step 4: Generate Orders ────────────────────────────────────────────────
    console.log("\n🛒  Generating orders (this may take a moment)...");

    const DAYS = 60;
    let totalOrders = 0;
    let totalItems  = 0;

    for (let dayIndex = 0; dayIndex < DAYS; dayIndex++) {
      const orderDate = daysAgo(DAYS - dayIndex);
      const isWeekend  = [0, 6].includes(new Date(orderDate).getDay());

      // Group products by category/supplier so we create one order per supplier per day
      const supplierOrders = {}; // supplierId → [{ product, qty }]

      for (const prod of PRODUCTS) {
        // Weekend bump: double probability for electronics & clothing
        let dayI = dayIndex;
        if (isWeekend && ["Electronics", "Clothing"].includes(prod.cat)) {
          dayI = Math.min(dayIndex + 8, DAYS - 1); // artificially boost progress
        }

        if (!shouldOrder(prod.trend, dayI, DAYS)) continue;

        const supplierId = supNameToId[SUPPLIERS[CAT_SUPPLIER_MAP[prod.cat]].name];
        if (!supplierOrders[supplierId]) supplierOrders[supplierId] = [];

        const qty = randInt(prod.baseQty[0], prod.baseQty[1]);
        supplierOrders[supplierId].push({
          product_id: productMap[prod.name].id,
          quantity:   qty,
          unit_price: prod.price,
        });
      }

      // Insert one order per supplier that has items today
      for (const [supplierId, items] of Object.entries(supplierOrders)) {
        if (!items.length) continue;

        const total = items.reduce((s, i) => s + i.quantity * i.unit_price, 0);

        // Insert order
        const [orderResult] = await conn.execute(
          "INSERT INTO orders (supplier_id, order_date, status, total_amount) VALUES (?, ?, 'received', ?)",
          [supplierId, orderDate, total]
        );
        const orderId = orderResult.insertId;

        // Insert order items
        for (const item of items) {
          await conn.execute(
            "INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES (?, ?, ?, ?)",
            [orderId, item.product_id, item.quantity, item.unit_price]
          );

          // Update product stock
          await conn.execute(
            "UPDATE products SET quantity = quantity + ? WHERE id = ?",
            [item.quantity, item.product_id]
          );

          // Log stock movement
          await conn.execute(
            `INSERT INTO stock_movements (product_id, type, quantity, reason, reference_id, reference_type)
             VALUES (?, 'in', ?, ?, ?, 'order')`,
            [item.product_id, item.quantity, `Seed: Order #${orderId} received`, orderId]
          );
          totalItems++;
        }
        totalOrders++;
      }

      // Progress log every 10 days
      if ((dayIndex + 1) % 10 === 0) {
        console.log(`   📅  Processed ${dayIndex + 1}/${DAYS} days — ${totalOrders} orders so far`);
      }
    }

    console.log(`\n✅  Seeding complete!`);
    console.log(`   📦  Orders created  : ${totalOrders}`);
    console.log(`   🧾  Order items      : ${totalItems}`);
    console.log(`   📂  Categories       : ${CATEGORIES.length}`);
    console.log(`   🏭  Suppliers        : ${SUPPLIERS.length}`);
    console.log(`   🛒  Products         : ${PRODUCTS.length}`);

  } catch (err) {
    console.error("❌  Seed error:", err.message);
  } finally {
    await conn.end();
  }
}

seed();
