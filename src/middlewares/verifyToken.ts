import { Request, Response, NextFunction } from "express"
import jwt from "jsonwebtoken"

interface UserData {
  id: number
  email: string
  username: string
}

interface ValidationRequest extends Request {
  userData: UserData
}

export const verifyToken = async (req: Request, res: Response, next: NextFunction) => {
  const validationReq = req as ValidationRequest
  const { authorization } = validationReq.headers

  if (!authorization) {
    return res.status(401).json({
      "message": "Unauthorized"
    })
  }

  try {
    const token = authorization.split(" ")[1]
    const secret = process.env.JWT_SECRET!

    const jwtDecode = jwt.verify(token, secret)

    validationReq.userData = jwtDecode as UserData
  } catch (error) {
    return res.status(403).json({
      "message": "Forbidden"
    })
  }
  next()
}