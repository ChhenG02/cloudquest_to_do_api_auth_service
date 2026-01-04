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

    // Generate token for the new user (just like login)
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
}