import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { NestExpressApplication } from '@nestjs/platform-express';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    rawBody: true,
  });
  app.enableCors();
  app.enableShutdownHooks();
  app.useBodyParser('json', { limit: '10mb' });

  await app.listen(3000);
}
bootstrap();
