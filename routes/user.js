import dotenv from "dotenv";
dotenv.config();

import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { nanoid } from "nanoid";
import { verifyAccessToken, updatedProfileURL } from "./auth.js";

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

/*Update the user's profile*/
router.put("/profile", verifyAccessToken, async (req, res) => {
  const profileURL = req.params.profileURL;
  if (!profileURL) {
    return res.status(400).send("Bad request");
  }
  try {
    const updatedProfile = await updatedProfileURL(req.body);
    res.status(200).json(updatedProfile);
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).send(error.message);
  }
});

/* Update the user's profile */

/**
 * /profile:
    put:
      summary: Update user profile
      description: Update user profile information
      security:
        - Bearer: []
      consumes:
        - application/json
      parameters:
        - in: body
          name: profile
          description: User profile information
          schema:
            type: object
            properties:
              username:
                type: string
              email:
                type: string
              phoneNumber:
                type: string
              address:
                type: string
              password:
                type: string
            required:
              - username
              - email
      responses:
        200:
          description: Profile updated successfully
          schema:
            type: object
            properties:
              message:
                type: string
        404:
          description: User not found
          schema:
            type: object
            properties:
              error:
                type: string
        500:
          description: Internal Server Error
          schema:
            type: object
            properties:
              error:
                type: string
 */

router.put("/profile", verifyAccessToken, async (req, res) => {
  const userId = req.user.id; // Get the user ID from the verified token
  const users = req.app.db.get("users");
  const user = users.find((user) => user.id === userId);
  if (!user) {
    return res.status(404).send("User not found");
  }
  try {
    // Update the user's profile information
    user.username = req.body.username || user.username;
    user.email = req.body.email || user.email;
    user.phoneNumber = req.body.phoneNumber || user.phoneNumber;
    user.address = req.body.address || user.address;
    // Hash the new password if provided
    if (req.body.password) {
      const hashedPassword = await bcrypt.hash(req.body.password, 10);
      user.password = hashedPassword;
    }
    // Save the updated user to the database
    await req.app.db.write();
    res.status(200).json({ message: "Profile updated successfully" });
  } catch (error) {
    console.error("Error updating profile:", error);
    res.status(500).send(error.message);
  }
});

export default router;
