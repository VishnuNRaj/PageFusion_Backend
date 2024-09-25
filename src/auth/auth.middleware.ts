import { Injectable, NestMiddleware, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request, Response, NextFunction } from 'express';
import { UsersService } from '../users/users.service';

@Injectable()
export class VerifyMiddleware implements NestMiddleware {
    constructor(
        private readonly jwtService: JwtService,
        private readonly usersService: UsersService,
    ) { }

    async use(req: Request, res: Response, next: NextFunction) {
        try {
            const token = req.headers['authorization'];
            console.log(token)
            if (!token) {
                throw new UnauthorizedException('No token provided');
            }
            let decoded;
            try {
                decoded = this.jwtService.verify(token);
            } catch (error) {
                if (error.name === 'TokenExpiredError') {
                    // @ts-ignore
                    const refreshToken = req.cookies("refreshToken")
                    if (refreshToken) {
                        try {
                            const refreshDecoded = this.jwtService.verify(refreshToken);
                            const user = await this.usersService.findOneById(refreshDecoded.id);

                            if (user) {
                                const newAccessToken = this.jwtService.sign({ id: user._id, verified: user.verified });
                                res.cookie("accessToken", newAccessToken)
                                req['user'] = user;
                                next();
                                return;
                            } else {
                                throw new UnauthorizedException('Invalid refresh token');
                            }
                        } catch (refreshError) {
                            throw new UnauthorizedException('Invalid or expired refresh token');
                        }
                    } else {
                        throw new UnauthorizedException('Token expired, refresh token required');
                    }
                } else {
                    throw new UnauthorizedException('Invalid token');
                }
            }

            const user = await this.usersService.findOneById(decoded.id);
            console.log(user)
            if (!user) {
                throw new UnauthorizedException('User not found');
            }

            req['user'] = {
                _id: user._id,
                name: user.name,
                verified: user.verified,
            };
            next();
        } catch (error) {
            console.log(error)
            return res.status(401).json({ status: false, message: error.message });
        }
    }
}
