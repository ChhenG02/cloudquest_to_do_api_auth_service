import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Like, Repository } from 'typeorm';
import { User } from './user.entity';
import { In } from 'typeorm';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private repo: Repository<User>,
  ) {}

  findByEmail(email: string) {
    return this.repo.findOne({ where: { email } });
  }

  findByUsername(username: string) {
    return this.repo.findOne({ where: { username } });
  }

  create(user: Partial<User>) {
    return this.repo.save(user);
  }

  searchUsers(query: string) {
    if (!query || query.trim().length < 2) {
      // Return empty array for short queries
      return Promise.resolve([]);
    }

    const searchTerm = `%${query.trim()}%`;

    return this.repo.find({
      where: [{ email: Like(searchTerm) }, { username: Like(searchTerm) }],
      take: 10, // Limit to 10 results
      select: ['id', 'email', 'username'],
    });
  }

  async findByIds(ids: string[]) {
    return this.repo.find({
      where: { id: In(ids) },
      select: ['id', 'email', 'username'],
    });
  }
}
