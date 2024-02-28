import {
  ConflictException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import * as speakeasy from 'speakeasy';
import { SignupDto } from './dto/signup.dto';
import { PrismaService } from 'src/prisma/prisma.service';
import { MailerService } from 'src/mailer/mailer.service';
import { SigninDto } from './dto/signin.dto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { ResetPasswordDemandDto } from './dto/resetPasswordDemand.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly mailerService: MailerService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async signup(signupDto: SignupDto) {
    const { email, password, username } = signupDto;
    // Vérifier si l'utilisateur est déjà inscrit
    const user = await this.prismaService.user.findUnique({ where: { email } });
    if (user) {
      throw new ConflictException('User already exists');
    }

    // Hasher le mot de passe
    const hash = await bcrypt.hash(password, 10);

    // Enregistrer l'utilisateur dans la base de données
    await this.prismaService.user.create({
      data: { email, username, password: hash },
    });

    // Envoyer un mail de confirmation
    await this.mailerService.sendSignupConfirmation(email);

    // Retourner une réponse de succès
    return { data: 'User successfully created' };
  }

  async signin(signinDto: SigninDto) {
    const { email, password } = signinDto;
    // Vérifier si l'utilisateur est déjà inscrit
    const user = await this.prismaService.user.findUnique({ where: { email } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Comparer le mot de passe
    const macth = await bcrypt.compare(password, user.password);
    if (!macth) {
      throw new UnauthorizedException('User or password not exists');
    }

    // Retourner un token jwt
    const playload = {
      sub: user.userId,
      email: user.email,
    };

    const token = this.jwtService.sign(playload, {
      expiresIn: '2h',
      secret: this.configService.get('SERCRET_KEY'),
    });

    return {
      token,
      user: {
        username: user.username,
        email: user.email,
      },
    };
  }

  async resetPasswordDemandDto(resetPasswordDemandDto: ResetPasswordDemandDto) {
    const { email } = resetPasswordDemandDto;
    // Vérifier si l'utilisateur est déjà inscrit
    const user = await this.prismaService.user.findUnique({ where: { email } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const code  = speakeasy.totp({
        secret: this.configService.get('OTP_CODE'),
        digits: 5,
        step: 60 * 10,
        encoding: 'base32'
    });
    const url = "http://localhost:3000/auth/reset-password-confirmation"

    await this.mailerService.sendResetPassword(email, url, code);

    return {data: "Reset password mail has been sent"};
  }
}
