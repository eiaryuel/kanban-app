import "dotenv/config"; // must stay the first import
import express from "express";
import cors from "cors";
import { ZodError } from "zod";
import authRoutes from "./routes/auth.js";

const app = express();

app.use(cors({ origin: process.env.CLIENT_URL }));
app.use(express.json());

app.get("/api/health", (req, res) => res.json({ status: "ok" }));
app.use("/api/auth", authRoutes);

// Central error handler
app.use((err, req, res, next) => {
  if (err instanceof ZodError) {
    return res
      .status(400)
      .json({ error: "Validation failed", details: err.issues });
  }
  console.error(err);
  res.status(500).json({ error: "Something went wrong" });
});

app.listen(process.env.PORT, () =>
  console.log(`Server running on http://localhost:${process.env.PORT}`),
);
