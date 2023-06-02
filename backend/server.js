const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { MongoClient, ServerApiVersion } = require("mongodb");
const port = process.env.PORT || 5000;
const cors = require("cors");

const app = express();

require("dotenv").config();

app.use(cors());
app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_USER}:6DfVbybcrG8WAb4S@cluster0.s0ga6m2.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    },
});

async function run() {
    try {
        const usersCollection = client.db("JWTAuth").collection("users");

        // Register route
        app.post("/register", async (req, res) => {
            const { username, phoneNumber, password } = req.body;

            // Check if username already exists
            const existingUser = await usersCollection.findOne({ username });
            if (existingUser) {
                return res
                    .status(409)
                    .json({ message: "Username already exists" });
            }

            // Hash the password
            const hashedPassword = await bcrypt.hash(password, 10);

            // Insert the user into the database
            const newUser = {
                username,
                phoneNumber,
                password: hashedPassword,
            };
            await usersCollection.insertOne(newUser);

            res.status(201).json({ message: "Registration successful" });
        });

        // Login route
        app.post("/login", async (req, res) => {
            const { username, password } = req.body;

            // Find the user by username
            const user = await usersCollection.findOne({ username });
            if (!user) {
                return res
                    .status(401)
                    .json({ message: "Invalid username or password" });
            }

            // Compare the provided password with the stored hashed password
            const passwordMatch = await bcrypt.compare(password, user.password);
            if (!passwordMatch) {
                return res
                    .status(401)
                    .json({ message: "Invalid username or password" });
            }

            // Generate JWT
            const token = jwt.sign({ userId: user._id }, "secret", {
                expiresIn: "1h",
            });

            res.status(200).json({ token });
        });

        // Protected route
        app.get("/protected", (req, res) => {
            // Verify the JWT from the Authorization header
            const token = req.headers.authorization;
            if (!token) {
                return res.status(401).json({ message: "No token provided" });
            }

            jwt.verify(token, "secret", (err, decoded) => {
                if (err) {
                    return res.status(401).json({ message: "Invalid token" });
                }

                // Token is valid, send a success message
                res.status(200).json({
                    message: "Protected route accessed successfully",
                });
            });
        });
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);

// Start the server
app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
