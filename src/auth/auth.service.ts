import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { User } from "../users/users.schema";
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { ConfigService } from '@nestjs/config';
import * as interfaces from "./auth.interfaces";
import * as nodemailer from 'nodemailer';

@Injectable()
export class AuthService {
    constructor(
        private usersService: UsersService,
        private jwtService: JwtService,
        private configService: ConfigService,
    ) { }

    async validatePassword(pass: string, password: string): Promise<boolean> {
        return pass && await bcrypt.compare(pass, password);
    }

    async validateUser(email: string): Promise<User | null> {
        return await this.usersService.findOneByEmail(email);
    }

    async login(data: interfaces.LoginRequest): Promise<interfaces.LoginResponse> {
        try {
            const { email, password, remember } = data;
            const user = await this.validateUser(email);

            if (!user || !await this.validatePassword(password, user.password)) {
                return { status: false, message: 'Invalid email or password' };
            }

            if (!user.verified) {
                return { status: false, message: 'Account not verified' };
            }

            const payload = { id: user._id, verified: user.verified };
            const accessToken = this.jwtService.sign(payload);

            let refreshToken = null;
            if (remember) {
                refreshToken = this.jwtService.sign(payload, { expiresIn: '7d' });
            }

            return {
                status: true,
                accessToken,
                refreshToken,
                message: "Login Successfull"
            };
        } catch (error) {
            return {
                status: false, message: 'Internal Server Error'
            }
        }
    }

    async signup(name: string, email: string, password: string): Promise<interfaces.SignupResponse> {
        const existingUser = await this.usersService.findOneByEmail(email);

        if (existingUser && !existingUser.verified) {
            this.sendVerificationEmail(existingUser);
            return { status: false, message: 'Account already exists but not verified. Verification email sent.' };
        } else if (existingUser) {
            return { status: false, message: 'Account already exists' };
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await this.usersService.create({
            name,
            email,
            password: hashedPassword,
            verified: false,
            twoStepVerification: false,
        });

        this.sendVerificationEmail(newUser);

        return { status: true, message: 'Signup successful. Verification email sent.' };
    }

    async verifyToken(token: string): Promise<interfaces.LoginResponse> {
        try {
            const response = this.jwtService.verify(token);
            const user = await this.usersService.findOneById(response.id);

            if (!user) {
                throw new UnauthorizedException('Invalid token');
            }

            if (user.verified) {
                return { status: false, message: 'Account already verified' };
            }

            user.verified = true;
            await user.save();
            const payload = { id: user._id, verified: user.verified };
            const accessToken = this.jwtService.sign(payload);

            return { status: true, message: 'Account verified successfully', accessToken };
        } catch (error) {
            if (error.name === 'TokenExpiredError') {
                return { status: false, message: 'Token expired. Please request a new verification email.' };
            }

            if (error instanceof UnauthorizedException) {
                return { status: false, message: 'Invalid token' };
            }

            return { status: false, message: 'Internal server error' };
        }
    }


    private async sendVerificationEmail(user: User) {
        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: this.configService.get<string>('EMAIL_USER'),
                pass: this.configService.get<string>('EMAIL_PASS'),
            },
        });

        const verificationLink = `${this.configService.get<string>("ORIGIN")}/verify/${this.jwtService.sign({ id: user._id }, { expiresIn: '1h' })}`;

        await transporter.sendMail({
            from: this.configService.get<string>('EMAIL_USER'),
            to: user.email,
            subject: 'Account Verification',
            text: `Please verify your account using this link: ${verificationLink}`,
        });
    }
}
