import { Controller, Post, Body, Get, Request, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  signup(@Body() dto: SignupDto) {
    return this.authService.signup(dto.username, dto.email, dto.password);
  }

  @Post('login')
  async login(@Body() dto: LoginDto) {
    return this.authService.login(dto.email, dto.password);
  }

  @Get('checkauth')
  async checkAuth(@Request() req) {
    const authHeader = req.headers.authorization;
    if (!authHeader) throw new UnauthorizedException('No token provided');

    const token = authHeader.replace('Bearer ', '');
    try {
      const payload = this.authService.verifyToken(token); // decode JWT
      return {
        accessToken: token, // original token
        payload,            // decoded payload
      };
    } catch {
      throw new UnauthorizedException('Invalid token');
    }
  }
}
