import { Low, JSONFileSync } from "lowdb";
import cors from "cors";
import express from "express";
import morgan from "morgan";
import userRouter from "./routes/user.js";
import swaggerUI from "swagger-ui-express";
import specs from "./swagger/swagger.js";
import bcrypt from "bcrypt";
import { nanoid } from "nanoid";
import jwt from "jsonwebtoken";

const app = express();
const PORT = process.env.PORT || 4000;

// Initialize the database
const adapter = new JSONFileSync("db.json");
const db = new Low(adapter);
await db.read();
db.data ||= { users: [] };
await db.write();

// Middleware
app.use(cors());
app.use(express.json());
app.use(morgan("dev"));
app.use("/api-docs", swaggerUI.serve, swaggerUI.setup(specs));

// Routes
app.get("/", (req, res) => {
  res.send("Welcome to the API!");
});

app.use("/user", userRouter);

// Sign-up route
app.post("/signup", async (req, res) => {
  const { username, password, email, phoneNumber, address } = req.body;

  // Check if the user already exists
  const existingUser = db.data.users.find((u) => u.username === username);
  if (existingUser) {
    return res.status(409).json({ error: "Username already taken" });
  }

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Create a new user object
  const newUser = {
    id: nanoid(),
    username,
    password: hashedPassword,
    email,
    phoneNumber,
    address,
  };

  // Add the user to the database
  db.data.users.push(newUser);
  await db.write();

  res.status(201).json({ message: "User registered successfully" });
});

// Sign-in route
app.post("/signin", async (req, res) => {
  const { username, password } = req.body;

  // Retrieve user data from the database (lowdb)
  const user = db.data.users.find((u) => u.username === username);

  if (!user) {
    return res.status(400).json({ error: "User not found" });
  }

  // Compare hashed password
  const passwordMatch = await bcrypt.compare(password, user.password);

  if (!passwordMatch) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  // Generate a JWT token
  const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
    expiresIn: "2h", // Set an expiration time
  });

  res.json({ accessToken: token });
});

// Middleware to verify JWT token and set user in request
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res
      .status(403)
      .json({ error: "A token is required for authentication" });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid Token" });
  }
};

// Route to get the logged-in user's data from the database
app.get("/user", verifyToken, async (req, res) => {
  // Retrieve user data from the database using the userId from JWT token
  const user = db.data.users.find((u) => u.id === req.user.userId);

  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  // Exclude password from the response
  const { password, ...userData } = user;

  res.json(userData);
});

// Start the server
app.listen(PORT, () => console.log(`The server is running on port ${PORT}`));
