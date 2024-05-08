const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const stripe = require("stripe")("sk_test_UjCD2kLt6KIOevQyMSHBXc2M00PnxwK3GU");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const app = express();
const port = 2000;
const JWT_TOKEN = "xe21-da#";

app.use(bodyParser.json());
app.use(cors());

const endpointSecret =
  "whsec_c58b0399f811a59246e633eedf0a17173c16c0a0b98bdb151fed74be872e25b6";

mongoose.connect("mongodb://localhost:27017/lbu_diab", {
  useUnifiedTopology: true,
});

const db = mongoose.connection;

db.on("error", console.error.bind(console, "MongoDb connection error: "));
db.once("open", () => {
  console.log("Connected to MongoDB");
});

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  credits: { type: Number, default: 0 },
});

const User = mongoose.model("User", userSchema);

// register endpoint
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      res.status(409).json({ message: "User already exists" });
    } else {
      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = new User({ name, email, password: hashedPassword });
      await newUser.save();
      res.status(201).json({ message: "Registration Successful" });
    }
  } catch (error) {
    console.error("Error registering user:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (user) {
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (isPasswordValid) {
        // set user object on request
        req.user = user;

        // generate JWT token
        const token = jwt.sign({ id: user._id }, JWT_TOKEN, {
          expiresIn: "24h",
        });

        res.status(200).json({
          token,
          user: { id: user._id, email: user.email, credits: user.credits },
        });
      } else {
        res.status(401).json({ message: "Invalid username or password" });
      }
    } else {
      res.status(401).json({ message: "Invalid username or password" });
    }
  } catch (error) {
    console.error("Error logging in: ", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/dashboard", authenticateToken, async (req, res) => {
  try {
    const userId = req.user && req.user.id;
    if (!userId) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found!" });
    }

    res.status(200).json({
      name: user.name,
      email: user.email,
      credits: user.credits,
    });
  } catch (error) {
    console.error("Error fetching user information: ", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/add-credits", authenticateToken, async (req, res) => {
  try {
    const userId = req.user && req.user.id;
    if (!userId) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found!" });
    }

    const { credits } = req.body;
    if (!credits || isNaN(credits)) {
      return res.status(400).json({ message: "Invalid credits amount!" });
    }

    user.credits += parseInt(credits);
    await user.save();

    res
      .status(200)
      .json({ message: "Credits added successfully", credits: user.credits });
  } catch (error) {
    console.error("Error adding credits: ", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// endpoint to create a payment intent
app.post("/create-payment-intent", authenticateToken, async (req, res) => {
  try {
    const { amount, currency } = req.body;
    const userId = req.user.id;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found!" });
    }
    const paymentIntent = await stripe.paymentIntents.create({
      amount,
      currency,
      metadata: {
        userId: userId,
        email: user.email,
      },
    });
    res.status(200).json({ clientSecret: paymentIntent.client_secret });
  } catch (error) {
    console.error("Error creating payment intent:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/create-checkout-session", authenticateToken, async (req, res) => {
  try {
    const { amount } = req.body;
    const userId = req.user.id;
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      line_items: [
        {
          price_data: {
            currency: "GBP",
            product_data: {
              name: "Credits",
            },
            unit_amount: amount * 100,
          },
          quantity: 1,
        },
      ],
      mode: "payment",
      success_url: "http://localhost:3000/success",
      cancel_url: "http://localhost:3000/cancel",
      metadata: { userId: userId },
    });

    res.status(200).json({ paymentUrl: session.url });
  } catch (error) {
    console.error("Error Creating checkout session", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post(
  "/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    console.log(`log: webhook link called:`);

    let data;
    let eventType;

    let webhookSecret;

    if (webhookSecret) {
    } else {
      data = req.body.data.object;
      eventType = req.body.type;
    }

    if (eventType === "checkout.session.completed") {
      const user = await User.findById(data.metadata.userId);
      user.credits += 5;
      await user.save();
    }
    res.status(200).end();
  }
);

app.post("/predict", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    // fetch user from database
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found!" });
    }

    // deduct 0.5 credits for prediction call
    const deductionAmount = 0.5;
    if (user.credits < deductionAmount) {
      return res.status(403).json({ message: "Insufficient Charges" });
    }
    user.credits -= deductionAmount;
    await user.save();

    const {
      Pregnancies,
      Glucose,
      BloodPressure,
      SkinThickness,
      Insulin,
      BMI,
      DiabetesPedigreeFunction,
      Age,
    } = req.body;
    const data = {
      Pregnancies,
      Glucose,
      BloodPressure,
      SkinThickness,
      Insulin,
      BMI,
      DiabetesPedigreeFunction,
      Age,
    };

    let prediction;

    // Call the Prediction Service
    await axios
      .post("http://localhost:8080/prediction", data)
      .then((response) => {
        console.log();
        prediction = response?.data?.data?.prediction;
        meta = response?.data?.data?.meta;
      });

    res
      .status(200)
      .json({ message: "Prediction Result", prediction, meta: meta });
  } catch (error) {
    console.log("Error Getting prediction: ", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) {
    res.status(401).json({ message: "Unauthorized" });
  }

  jwt.verify(token, JWT_TOKEN, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Forbidden" });
    }
    req.user = user;
    next();
  });
}

app.listen(port, () => {
  console.log(`Node.js server listening at http://localhost:${port}`);
});
