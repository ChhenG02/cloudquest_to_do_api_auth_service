import { Injectable, UnauthorizedException } from '@nestjs/common';
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
    const hash = await bcrypt.hash(password, 10);
    return this.usersService.create({
      username,
      email,
      password: hash,
    });
  }

  async login(email: string, password: string) {
    const user = await this.usersService.findByEmail(email);
    if (!user) throw new UnauthorizedException();

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) throw new UnauthorizedException();

    const payload = { sub: user.id, email: user.email };

    return {
      accessToken: this.jwtService.sign(payload),
      payload,
    };
  }

  // verify a JWT and return payload
  verifyToken(token: string) {
    try {
      return this.jwtService.verify(token); // decoded payload
    } catch (err) {
      throw new UnauthorizedException('Invalid token');
    }
  }
}
