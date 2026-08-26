import { Controller, Post, Get, Body, Query, Param, Headers, Req } from '@nestjs/common';
declare function use(x:any):any;
class CreateDto { a: string; }

@Controller('t')
export class TController {
  // ADVERSARIAL: identifier names deliberately contradict the decorators.
  @Post('a') a1(@Query() body: any) { use(body); }          // must be QUERY
  @Post('b') a2(@Body() query: any) { use(query); }         // must be BODY
  @Get('c')  a3(@Param('id') headers: string) { use(headers); }  // must be PARAM
  @Get('d')  a4(@Headers('h') param: string) { use(param); }     // must be HEADER

  // correct-name baselines
  @Post('e') a5(@Body() banana: CreateDto) { use(banana); }
  @Get('f')  a6(@Query() orange: any) { use(orange); }

  // unrelated parameter must receive NOTHING
  @Post('g') a7(@Body() body: any, unrelated: any) { use(body); use(unrelated); }

  // multiple decorators on one method, distinct families
  @Post('h') a8(@Param('id') id: string, @Body() b: any, @Query() q: any) { use(id); use(b); use(q); }

  // alias + destructuring downstream of a decorated parameter
  @Post('i') a9(@Body() b: any) {
    const alias = b;
    const { field } = b;
    use(alias); use(field);
  }

  // undecorated method in a decorated controller
  helper(x: any) { use(x); }
}

// undecorated class with identical shape -> must yield nothing
export class NotAController {
  a1(body: any) { use(body); }
}
