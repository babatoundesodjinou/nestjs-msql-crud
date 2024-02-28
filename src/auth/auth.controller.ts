import { Body, Controller, Post } from '@nestjs/common';
import { SignupDto } from './dto/signup.dto';
import { AuthService } from './auth.service';
import { SigninDto } from './dto/signin.dto';
import { ResetPasswordDemandDto } from './dto/resetPasswordDemand.dto';

@Controller('auth')
export class AuthController {

    constructor(private readonly authService: AuthService){}

    @Post('signup')
    singnup(@Body() signupDto: SignupDto){
        return this.authService.signup(signupDto)
    }
    
    @Post('signin')
    singnin(@Body() signinDto: SigninDto){
        return this.authService.signin(signinDto)
    }
    
    @Post('reset-password')
    resetPasswordDemand(@Body() resetPasswordDemandDto: ResetPasswordDemandDto){
        return this.authService.resetPasswordDemandDto(resetPasswordDemandDto)
    }


}
