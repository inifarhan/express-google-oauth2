import express from "express"
import dotenv from "dotenv"
import UserRoutes from "./routes/UserRoutes"

dotenv.config()
const app = express()

// Middlewares
app.use(express.json())

// Routes
app.use(UserRoutes)

app.listen(5000, () => console.log("Server running on port 5000"))