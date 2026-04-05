import { Request, Response, NextFunction } from 'express';
import { UnauthorizedError } from '../utils/errors';
import logger from '../utils/logger';

interface AuthRequest extends Request {
  apiKey?: string;
}

const authMiddleware = (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const apiKey = req.headers['x-api-key'] as string;

    if (!apiKey) {
      logger.warn('Missing API key in request');
      throw new UnauthorizedError('API key required');
    }

    if (apiKey !== process.env.API_KEY) {
      logger.warn(`Invalid API key attempt: ${apiKey}`);
      throw new UnauthorizedError('Invalid API key');
    }

    req.apiKey = apiKey;
    next();
  } catch (error) {
    next(error);
  }
};

export default authMiddleware;