import { User } from '../models/user.model.js';
import { verifyToken } from '../utils/jwt.js';

/**
 * TODO: Authenticate user using JWT
 *
 * 1. Extract Authorization header from req.headers.authorization
 * 2. Check if header exists and starts with "Bearer "
 *    - If not: return 401 with { error: { message: "No token provided" } }
 * 3. Extract token (split by space and get second part)
 * 4. Verify token using verifyToken(token) - wrap in try/catch
 *    - If invalid: return 401 with { error: { message: "Invalid token" } }
 * 5. Find user by decoded.userId
 *    - If not found: return 401 with { error: { message: "Invalid token" } }
 * 6. Attach user to req.user
 * 7. Call next()
 */
export async function authenticate(req, res, next) {
  try {
    // extract from header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: { message: "No token provided" } });
    }

    const token = authHeader.split(' ')[1];

    // verify token
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({ error: { message: 'Invalid token' } });
    }

    // find user
    const user = await User.findById(decoded.userId);

    // user not found
    if (!user) {
      return res.status(401).json({ error: { message: 'Invalid token' } });
    }

    // attach minimal user info
    req.user = { userId: user._id, email: user.email, role: user.role };

    return next();
  } catch (error) {
    return res.status(401).json({ error: { message: 'Invalid token' } });
  }
}
