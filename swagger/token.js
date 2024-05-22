import axios from "axios";
import jwt from "jsonwebtoken";

const protectedEndpointUrl = "http://localhost:4000/protected-endpoint";
const username = "admin";
const password = "admin";
const secretKey = "8e7152d0eb52c340579f2d70a28eaf1a2c5ba1c5";

/**
 * @swagger
 * /token:
 *   post:
 *     summary: Generate a JWT token
 *     requestBody:
 *       content:
 *         application/x-www-form-urlencoded:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *             required:
 *               - username
 *               - password
 *     responses:
 *       '200':
 *         description: JWT token generated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   description: The generated JWT token
 *       '401':
 *         description: Unauthorized
 */

// Function to generate a JWT token
/**
 * Generates a JWT token.
 * @param {string} username - The user's username.
 * @returns {string|null} - The generated JWT token or null if an error occurs.
 */
export async function generateJwtToken(username) {
  try {
    // Create payload (claims)
    const payload = {
      username: username,
    };

    // Generate the JWT token with a 1-hour expiration
    const token = jwt.sign(payload, secretKey, { expiresIn: "1h" });

    return token;
  } catch (error) {
    console.error("Error generating JWT token:", error.message);
    return null;
  }
}

/**
 * Verifies a JWT token.
 * @param {string} token - The JWT token to verify.
 * @returns {object|null} - The decoded payload or null if verification fails.
 */
export function verifyJwtToken(token) {
  try {
    const decoded = jwt.verify(token, secretKey);
    return decoded;
  } catch (error) {
    console.error("Error verifying JWT token:", error.message);
    return null;
  }
}

export default { generateJwtToken, verifyJwtToken };
