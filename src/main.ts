import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';
import * as cookieParser from "cookie-parser"
import { json, urlencoded } from "body-parser"
async function NestJs() {
  const app = await NestFactory.create(AppModule);
  app.use(cookieParser())
  const configService = app.get(ConfigService);
  const origin = configService.get<string>('ORIGIN');

  app.enableCors({
    origin: origin,
    methods: 'GET,POST,PUT,DELETE',
    credentials: true,
  });
  app.use(json({ limit: "250mb" }));
  app.use(urlencoded({ limit: '250mb', extended: true }));
  await app.listen(6700);
}
NestJs();
