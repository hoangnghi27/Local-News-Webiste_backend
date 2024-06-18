import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { nanoid } from "nanoid";

const router = express.Router();

/**
 * @swagger
 * /signup:
 *   post:
 *     security:
 *       - BearerAuth: []
 *     summary: Sign up to the application
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - password
 *               - email
 *               - phoneNumber
 *               - address
 *             properties:
 *               username:
 *                 type: string
 *                 description: The desired username for registration
 *               password:
 *                 type: string
 *                 description: The user's password (will be hashed before storage)
 *               email:
 *                 type: string
 *                 format: email
 *                 description: The user's email address
 *               phoneNumber:
 *                 type: string
 *                 description: The user's phone number
 *               address:
 *                 type: string
 *                 description: The user's address
 *     responses:
 *       201:
 *         description: User created successfully
 *       400:
 *         description: Username already exists or invalid request
 *       500:
 *         description: Server error during user creation
 */

// Sign-up route
router.post("/signup", async (req, res) => {
  const users = req.app.db.get("users");
  const existingUser = users.find(
    (user) => user.username === req.body.username
  );
  if (existingUser) {
    return res.status(400).send("Username already exists");
  }
  try {
    // Hash the user's password before storing it
    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    // Create a new user object with additional fields
    const user = {
      id: nanoid(),
      username: req.body.username,
      password: hashedPassword,
      email: req.body.email,
      phoneNumber: req.body.phoneNumber,
      address: req.body.address,
    };

    // Add the user to the database
    users.push(user);
    await req.app.db.write();

    // Respond with a success status
    res.status(201).send();
  } catch (error) {
    // Handle server error during user creation
    console.error("Error creating user:", error);
    res.status(500).send();
  }
});

/**
 * @swagger
 * /signin:
 *   post:
 *     security:
 *       - BearerAuth: []
 *     summary: Sign in to the application
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Returns a JSON Web Token if the sign-in was successful
 *       400:
 *         description: Cannot find user
 *       500:
 *         description: Server error
 */

// Sign-in route
router.post("/signin", async (req, res) => {
  const users = req.app.db.get("users");
  const user = users.find((user) => user.username === req.body.username);
  if (!user) {
    return res.status(400).send("Cannot find user");
  }
  try {
    if (await bcrypt.compare(req.body.password, user.password)) {
      const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
        expiresIn: "2h",
      });
      res.json({ accessToken: token });
    } else {
      res.send("Not Allowed");
    }
  } catch {
    res.status(500).send();
  }
});

<<<<<<< HEAD
/**
 * @swagger
 * /logout:
 *   get:
 *     summary: Logs out the user
 *     description: This endpoint clears the JWT token from the client side storage by sending a response without a token.
 *     responses:
 *       200:
 *         description: Successfully logged out
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 accessToken:
 *                   type: string
 *                   description: The access token for the user. Will be null after logout.
 *                   example: null
 */

router.get("/logout", (req, res) => {
  // Clear the token from the client side storage by sending a response without token
  res.json({ accessToken: null });
=======
/*Update the user's profile (I took reference from the website)*/
router.put("/profile", verifyAccessToken, async (req, res) => {
  const profileURL = req.params.profileURL;
  if (!profileURL) {
    return res.status(400).send("Bad request");
  }
  try {
    const updatedProfile = await updatedProfileURL(req.body);
    res.status(200).json(updatedProfile);
  } catch (error) {
    res.status(500).send();
  }
>>>>>>> 35f69ea50ad07fdab05c1cfe5f7c60e67eb9569c
});

export default router;
