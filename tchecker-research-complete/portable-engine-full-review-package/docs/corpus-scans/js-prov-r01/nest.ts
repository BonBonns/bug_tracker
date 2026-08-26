import { Controller, Post, Body, Query, Param, Headers } from '@nestjs/common';
declare function use(x: any): any;
@Controller('users')
export class UsersController {
  @Post('login')
  login(@Body() body: any, @Query('q') q: string, @Param('id') id: string, @Headers('h') h: string) {
    use(body.username); use(q); use(id); use(h);
  }
}
