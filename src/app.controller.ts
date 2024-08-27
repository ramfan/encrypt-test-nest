import {
  Controller,
  Get,
  Patch,
  Post,
  UploadedFile,
  UseInterceptors,
  Body,
  Header,
} from '@nestjs/common';
import { AppService } from './app.service';
import { FileInterceptor } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import e from 'express';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get('/ping')
  check() {
    return 'pong';
  }

  @Get('/key')
  async getKey() {
    return await this.appService.getPublicKey();
  }

  @Patch('/decrypt')
  decryptFile(@Body('fileName') fileName: string) {
    this.appService.decryptFile(fileName);
    return 'ok';
  }

  @Post('/decryptText')
  @Header('Content-Type', 'application/json')
  async decryptText(@Body() msg: { message: string; key: string; iv: string }) {
    return await this.appService.decryptText(msg.message, msg.key, msg.iv);
  }

  @Post('upload')
  @UseInterceptors(
    FileInterceptor('file', {
      storage: diskStorage({
        destination: './files/',
        filename(
          req: e.Request,
          file: Express.Multer.File,
          callback: (error: Error | null, filename: string) => void,
        ) {
          callback(null, file.originalname);
        },
      }),
    }),
  )
  uploadFile(
    @UploadedFile() file: Express.Multer.File,
    @Body() msg: { key: string; iv: string },
  ) {
    this.appService.saveAESKeyAndIVinFile(msg, file.originalname);
    return 'ok';
  }
}
