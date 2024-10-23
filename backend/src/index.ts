import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
// import jwt from '';

const app = new Hono();
const prisma = new PrismaClient();
const { Pool } = require('pg');
const bodyParser = require("body-parser");


app.use('*', cors({
  origin: 'http://localhost:3000', 
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE'], 
  allowHeaders: ['Content-Type', 'Authorization'], 
}));

// root endpoint
app.get('/', (c) => {
  return c.text('Hello!');
});

// assigning role endpoint
app.post('/roles', async (c) => {
  const { name, description } = await c.req.json();

  // Validate that 'name' is provided
  if (!name) {
    return c.json({ message: 'Role name is required' }, 400);
  }

  // Check if the role already exists
  const existingRole = await prisma.role.findUnique({
    where: { name }, // Ensure 'name' is used correctly here
  });

  if (existingRole) {
    return c.json({ message: 'Role already exists' }, 400);
  }

  // Create the new role
  try {
    const newRole = await prisma.role.create({
      data: {
        name,
        description,
      },
    });

    return c.json({ message: 'Role created successfully', role: newRole }, 201);
  } catch (error) {
    return c.json({ message: 'Error creating role', error: error.message }, 500);
  }
});

// Sign-up endpoint
app.post('/signup', async (c) => {
  const { username, password, hint, roleId } = await c.req.json();

  // Validate input fields
  if (!username || !password) {
    return c.json({ message: 'Username and password are required' }, 400);
  }

  const trimmedUsername = username.trim();
  const trimmedHint = hint ? hint.trim() : null;

  // Check lengths
  if (trimmedUsername.length > 25) {
    return c.json({ message: 'Username must be 25 characters or fewer' }, 400);
  }

  if (password.length > 50) {
    return c.json({ message: 'Password must be 50 characters or fewer' }, 400);
  }

  if (trimmedHint && trimmedHint.length > 100) {
    return c.json({ message: 'Hint must be 100 characters or fewer' }, 400);
  }

  // Check if username already exists
  const existingUser = await prisma.user.findUnique({
    where: { username: trimmedUsername },
  });

  if (existingUser) {
    return c.json({ message: 'Username already exists' }, 400);
  }

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Create the new user
  try {
    console.log('Data to insert:', {
      username: trimmedUsername,
      password: hashedPassword,
      hint: trimmedHint,
      roleId: roleId || null,
    });

    const newUser = await prisma.user.create({
      data: {
        username: trimmedUsername,
        password: hashedPassword,
        hint: trimmedHint,
        roleId: roleId || null,
      },
    });

    return c.json({ message: 'User created successfully', user: newUser }, 201);
  } catch (error) {
    console.error('Error details:', error);
    return c.json({ message: 'Error creating user', error: error.message }, 500);
  }
});

// Login endpoint
app.post('/login', async (c) => {
  const { username, password } = await c.req.json();

  // Find the user by username
  const user = await prisma.user.findUnique({
    where: { username },
    include: { role: true },  // Include role for later role-based checks
  });

  if (!user) {
    return c.json({ message: 'Invalid username or password' }, 400);
  }

  // Verify password
  const validPassword = await bcrypt.compare(password, user.password);

  if (!validPassword) {
    return c.json({ message: 'Invalid username or password' }, 400);
  }

  // Set a cookie with the user's ID (or some unique identifier)
  c.header('Set-Cookie', `userId=${user.id}; HttpOnly; Path=/`);

  return c.json({ message: 'Login successful', user: { username: user.username, role: user.role.name } });
});

//postgresSQL connection
const pool = new Pool({
  user: 'tshering',
  host: 'localhost',
  database: 'parking_db',
  password: 'software@321',
  port: 5432,
});

// dzongkhag endpoint
app.get("/dzongkhags", async (c) => {
  try {
    const result = await pool.query("SELECT * FROM Dzongkhag");
    return c.json(result.rows); // Correct way to return JSON in Hono
  } catch (error) {
    console.error("Error fetching dzongkhag data:", error);
    return c.json({ error: "Failed to fetch dzongkhag data" }, 500); // Use c.json and pass the status code correctly
  }
});

// parking_area endpoint
app.get("/parking_areas", async (c) => {
  try {
    const result = await pool.query("SELECT * FROM parking_area");
    return c.json(result.rows); // Correct way to return JSON in Hono
  } catch (error) {
    console.error("Error fetching parking area data:", error);
    return c.json({ error: "Failed to fetch parking area data" }, 500); // Use c.json and pass the status code correctly
  }
});

// parking _detail endpoint
app.get("/parking_details", async (c) => {
  try {
    const result = await pool.query("SELECT * FROM parking_detail");
    return c.json(result.rows); // Correct way to return JSON in Hono
  } catch (error) {
    console.error("Error fetching parking detail data:", error);
    return c.json({ error: "Failed to fetch parking detail data" }, 500); // Use c.json and pass the status code correctly
  }
});

// parking _slots endpoint
app.get("/parking_slots", async (c) => {
  try {
    const result = await pool.query("SELECT * FROM parking_slots");
    return c.json(result.rows); // Correct way to return JSON in Hono
  } catch (error) {
    console.error("Error fetching parking slot data:", error);
    return c.json({ error: "Failed to fetch parking slot data" }, 500); // Use c.json and pass the status code correctly
  }
});

// API endpoint to add data to the database
app.post("/add_data", async (c) => {
  const { parkingarea_id, parking_location, dzongkhag_id } = await c.req.json();

  try {
    const result = await pool.query("INSERT INTO parking_area (parkingarea_id, parking_location, dzongkhag_id) VALUES ($1, $2, $3)", [parkingarea_id, parking_location, dzongkhag_id]);
    return c.json({ message: "Data added successfully" }, 201);
  } catch (error) {
    console.error("Error adding data to the database:", error);
    return c.json({ error: "Failed to add data to the database" }, 500);
  }
});

// start and stop the python script




const port = 9999;
console.log(`Server is running on port ${port}`);

serve({
  fetch: app.fetch,
  port,
});
