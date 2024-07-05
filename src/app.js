import cookieParser from "cookie-parser";
import cors from "cors";
import express from "express";

const app = express();

app.get("/test", (req, res, next) => {
  res.json({ test: "hello" });
});

// middlewares
app.use(
  cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true,
  })
);
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(cookieParser());

// routes
import userRoutes from "./routes/user.route.js";

app.use("/api/v1/users", userRoutes);

export default app;
