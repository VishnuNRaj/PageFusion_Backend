import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema()
export class Pdf extends Document {
  @Prop({ required: true })
  userId: string;

  @Prop({ required: true })
  fileName: string;

  @Prop({ required: true })
  filePath: string;

  @Prop({ required: true, default: "pagefusion" })
  key: string;

  // @Prop({ required: true })
  // cipher: string;
}

export const PdfSchema = SchemaFactory.createForClass(Pdf);
