import { Request, Response } from "express"
import { PrismaClient } from "@prisma/client"
import * as bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
import { google } from "googleapis"

const prisma = new PrismaClient()

// REGISTER
export const register = async (req: Request, res: Response) => {
  try {
    const { email, username, password } = req.body

    if (!email) {
      return res.status(400).json({
        "message": "Email is required"
      })
    }
    if (!username) {
      return res.status(400).json({
        "message": "Username is required"
      })
    }
    if (!password) {
      return res.status(400).json({
        "message": "Password is required"
      })
    }
    
    const user = await prisma.user.findUnique({
      where: {
        email
      }
    })

    if (user) {
      return res.status(400).json({
        "message": "Email is already exist"
      })
    }

    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(password, salt)

    const result = await prisma.user.create({
      data: {
          username,
          email,
          password: hashedPassword,
      }
    })

    res.status(201).json({
      "message": "User created",
      "data": result
    })
  } catch (error) {
    console.log(error)
  }
}

// LOGIN
export const login = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body

    if (!email) {
      return res.status(400).json({
        "message": "Email is required"
      })
    }
    if (!password) {
      return res.status(400).json({
        "message": "Password is required"
      })
    }

    const user = await prisma.user.findUnique({
      where: {
        email
      }
    })

    if (!user) {
      return res.status(404).json({
        "message": "User doesnt exist"
      })
    }
    if (!user.password) {
      return res.status(404).json({
        "message": "User pasword is not set"
      })
    }

    const isPasswordValid = await bcrypt.compare(password, user.password)

    if (!isPasswordValid) {
      return res.status(401).json({
        "message": "Password is wrong"
      })
    }

    const payload = {
      id: user.id,
      email: user.email,
      username: user.username
    }
    const secret = process.env.JWT_SECRET!
    const expiresIn = 60 * 60 * 1

    const token = jwt.sign(payload, secret, { expiresIn: expiresIn })
    
    res.json({ token })
  } catch (error) {
    console.log(error)
  }
}

// GOOGLE REGISTER
const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  "http://localhost:5000/auth/google/callback"
)

const scopes = [
  'https://www.googleapis.com/auth/userinfo.email',
  'https://www.googleapis.com/auth/userinfo.profile',
];

const authorizationUrl = oauth2Client.generateAuthUrl({
  access_type: 'offline',
  scope: scopes,
  include_granted_scopes: true
});

// Google login
export const googleLogin = (req: Request, res: Response) => {
  res.redirect(authorizationUrl)
}

// Google callback login
export const googleLoginCallback = async (req: Request, res: Response) => {
  try {
    const { code } = req.query

    const { tokens } = await oauth2Client.getToken(code as string)

    oauth2Client.setCredentials(tokens);

    const oauth2 = google.oauth2({
      auth: oauth2Client,
      version: 'v2'
    })

    const { data } = await oauth2.userinfo.get()

    if (!data.email || !data.name) {
      return res.json({
        data
      })
    }

    let user = await prisma.user.findUnique({
      where: {
        email: data.email
      }
    })

    if (!user) {
      user = await prisma.user.create({
        data: {
          email: data.email,
          username: data.name
        }
      })
    }

    const payload = {
      id: user.id,
      email: user.email,
      username: user.username
    }
    const secret = process.env.JWT_SECRET!
    const expiresIn = 60 * 60 * 1

    const token = jwt.sign(payload, secret, { expiresIn: expiresIn })
    
    // Redirect ke frontend
    // return res.redirect(`http://localhost:3000/auth-success?token=${token}`)

    res.json({ token })
  } catch (error) {
    console.log(error)
    return res.redirect("/auth/google")
  }
}