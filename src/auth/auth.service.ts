import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { UsersService } from '../users/users.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  async signup(username: string, email: string, password: string) {
    const existingUser = await this.usersService.findByEmail(email);
    if (existingUser) {
      throw new BadRequestException('Email already exists');
    }

    const existingByUsername = await this.usersService.findByUsername(username);
    if (existingByUsername) {
      throw new BadRequestException('Username already taken');
    }

    const hash = await bcrypt.hash(password, 10);
    const user = await this.usersService.create({
      username,
      email,
      password: hash,
    });

    const payload = { sub: user.id, email: user.email };
    const accessToken = this.jwtService.sign(payload);

    return {
      accessToken,
      payload,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
      },
    };
  }

  async login(email: string, password: string) {
    const user = await this.usersService.findByEmail(email);
    if (!user) {
      throw new UnauthorizedException('Invalid Credentials');
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      throw new UnauthorizedException('Invalid Credentials');
    }

    const payload = { sub: user.id, email: user.email };

    return {
      accessToken: this.jwtService.sign(payload),
      payload,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
      },
    };
  }

  verifyToken(token: string) {
    try {
      return this.jwtService.verify(token);
    } catch (err) {
      throw new UnauthorizedException('Invalid token');
    }
  }

  // ✅ NEW: Search users method
  async searchUsers(query: string, currentUserId: string) {
    if (!query || query.trim().length < 2) {
      return [];
    }

    // Use the UsersService to search
    const users = await this.usersService.searchUsers(query.trim());
    
    // Filter out current user and format response
    return users
      .filter(user => user.id !== currentUserId)
      .map(user => ({
        id: user.id,
        email: user.email,
        username: user.username,
      }));
  }
  async getUsersByIds(ids: string[], currentUserId?: string) {
  if (!ids || ids.length === 0) return [];

  const uniqueIds = Array.from(new Set(ids));

  // ✅ You need a UsersService method for this:
  const users = await this.usersService.findByIds(uniqueIds);

  return users
    .filter(u => (currentUserId ? u.id !== currentUserId : true))
    .map(u => ({
      id: u.id,
      email: u.email,
      username: u.username,
    }));
}

}