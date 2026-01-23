import { Controller, Post, Body, Get, Request, UnauthorizedException, UseGuards, Query } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { JwtAuthGuard } from './jwt.guard';
import { BatchUsersDto } from './dto/batch-users.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  async signup(@Body() dto: SignupDto) {
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
      const payload = this.authService.verifyToken(token); 
      return {
        accessToken: token, 
        payload,
        user: {
          id: payload.sub,
          email: payload.email,
        }
      };
    } catch {
      throw new UnauthorizedException('Invalid token');
    }
  }

    @Get('users/search')
  @UseGuards(JwtAuthGuard) // Protect this endpoint
  async searchUsers(@Query('q') query: string, @Request() req) {
    // Pass the current user ID to exclude from results
    const currentUserId = req.user?.sub || req.user?.id;
    return this.authService.searchUsers(query, currentUserId);
  }
    @Post('users/batch')
  @UseGuards(JwtAuthGuard)
  async getUsersByIds(@Body() dto: BatchUsersDto, @Request() req) {
    // optional: exclude current user from results
    const currentUserId = req.user?.sub || req.user?.id;
    return this.authService.getUsersByIds(dto.ids, currentUserId);
  }
}