import { Module, MiddlewareConsumer, RequestMethod, forwardRef } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { PdfController } from './pdf.controller';
import { PdfService } from './pdf.service';
import { Pdf, PdfSchema } from './pdf.schema';
import { UsersModule } from '../users/users.module';
import { AuthModule } from '../auth/auth.module';
import { VerifyMiddleware } from '../auth/auth.middleware';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: Pdf.name, schema: PdfSchema }]),
    forwardRef(() => UsersModule),
    forwardRef(() => AuthModule),
  ],
  controllers: [PdfController],
  providers: [PdfService],
  exports: [PdfService],
})
export class PdfModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(VerifyMiddleware)
      .forRoutes({ path: 'pdf/save', method: RequestMethod.POST },
        { path: 'pdf/get', method: RequestMethod.POST },
        { path: 'pdf/key', method: RequestMethod.POST },
        { path: 'pdf/all', method: RequestMethod.GET },
      );
  }
}
