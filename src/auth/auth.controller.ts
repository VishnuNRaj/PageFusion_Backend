// auth.controller.ts
import { Controller, Request, Post, UseGuards, Get, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './auth.guard';
import CustomRequest from 'src/app.customRequest';
import { Response } from 'express';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) { }

    @Post('login')
    async login(@Request() req: CustomRequest, @Res() res: Response) {
        const response = await this.authService.login(req.body);
        if (response.status) {
            res.cookie('refreshToken', response.refreshToken, { httpOnly: true, secure: true });
        }
        return res.status(!response || !response.status ? 401 : 200).json(response)
    }

    @Post('signup')
    async signup(@Request() req: CustomRequest, @Res() res: Response) {
        const { name, email, password } = req.body;
        const response = await this.authService.signup(name, email, password);
        return res.status(!response || !response.status ? 401 : 200).json(response)
    }

    @Get('verifyToken')
    async verifyToken(@Request() req: CustomRequest, @Res() res: Response) {
        const token = req.headers.authorization;
        const response = await this.authService.verifyToken(token as string);
        console.log(response)
        return res.status(!response || !response.status ? 401 : 200).json(response)
    }

    @Get("verify")
    async verify(@Request() req: CustomRequest, @Res() res: Response) {
        const user = req['user'];
        if (user) {
            return res.status(200).json({
                status: true,
                message: 'User verified successfully',
                user: {
                    id: user._id,
                    email: user.email,
                    verified: user.verified,
                    name: user.name,
                    twoStepVerification: user.twoStepVerification
                }
            });
        }
        return res.status(401).json({
            status: false,
            message: 'Unauthorized'
        });
    }

    @UseGuards(JwtAuthGuard)
    @Get('profile')
    getProfile(@Request() req) {
        return req.user;
    }
}
