import express from "express"
import { getUsers } from "../controllers/UserController"
import {
  googleLogin,
  googleLoginCallback,
  login,
  register
} from "../controllers/AuthController"
import { verifyToken } from "../middlewares/verifyToken"

const router = express.Router()

router.get("/users", verifyToken, getUsers)
router.post("/auth/register", register)
router.post("/auth/login", login)
router.get("/auth/google", googleLogin)
router.get("/auth/google/callback", googleLoginCallback)

export default router