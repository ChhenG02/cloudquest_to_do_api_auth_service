import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { NestExpressApplication } from '@nestjs/platform-express';
import { join } from 'path';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  // ✅ Correct defaults for API Gateway
  const PORT = Number(process.env.PORT) || 8000;
  const CORS_ORIGIN =
    process.env.CORS_ORIGIN || 'http://localhost:3000';

  app.enableCors({
    origin: CORS_ORIGIN.split(','), // supports multiple origins if needed
    credentials: false, // ✅ IMPORTANT (Bearer token auth)
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  });

  app.useStaticAssets(join(__dirname, '..', 'public'));

  await app.listen(PORT, '0.0.0.0');

  console.log(`✅ API Gateway running on port ${PORT}`);
  console.log(`✅ CORS enabled for: ${CORS_ORIGIN}`);
}

bootstrap();
