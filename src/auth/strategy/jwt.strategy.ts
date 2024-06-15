import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    configService: ConfigService,
    private prismaService: PrismaService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get('JWT_SECRET'),
    });
  }

  async validate(payload: {
    id: number;
    email: string;
    iat: number;
    exp: number;
  }) {
    if (new Date(payload.exp * 1000).getTime() < new Date().getTime()) {
      throw new Error('Token expired');
    }
    const user = await this.prismaService.user.findUnique({
      where: {
        id: payload.id,
      },
    });
    delete user.hash;
    return user;
  }
}
