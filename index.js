import { Low } from "lowdb";
import { JSONFileSync } from "lowdb/node";
import cors from "cors";
import express from "express";
import morgan from "morgan";
import userRouter from "./routes/user.js";
import swaggerUI from "swagger-ui-express";
import specs from "./swagger/swagger.js";
import { generateJwtToken } from "./swagger/token.js";
import bcrypt from "bcrypt";
import { nanoid } from "nanoid";
import jwt from "jsonwebtoken";

const app = express();

const PORT = process.env.PORT || 4000;

const defaultData = { users: [] };

// const adapter = new JSONFile("db.json");
const db = new Low(new JSONFileSync("db.json"), {});

db.read();

db.data = defaultData;
db.write();

app.db = db;

app.use("/api-docs", swaggerUI.serve, swaggerUI.setup(specs));
app.use(morgan("dev"));

app.use(cors());

app.use(express.json());

app.post("/token", async (req, res) => {
  const { username, password } = req.body;
  try {
    const token = await generateJwtToken(username, password);
    if (token) {
      res.json({ token }); // Return the generated JWT token
    } else {
      res.status(401).json({ error: "Failed to generate JWT token" });
    }
  } catch (error) {
    console.error("Error generating JWT token:", error.message);
    res.status(401).json({ error: error.message });
  }
});

app.get("/", (req, res) => {
  res.send("Welcome to the API!");
});

// app.use("/books", booksRouter);
app.use("/user", userRouter);
// Sign-up route
app.post("/signup", async (req, res) => {
  const { username, password, email, phoneNumber, address } = req.body;
  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);
  // Create a new user object
  if (!db.data.users) {
    db.data.users = [];
  }
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
  db.write(); // Write data to the file

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
  const token = jwt.sign({ userId: user.id }, "your-secret-key", {
    expiresIn: "2h", // Set an expiration time
  });

  res.json({ accessToken: token });
});

app.listen(PORT, () => console.log(`The server is running on port ${PORT}`));
