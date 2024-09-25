import { Controller, Post, Body, Get, Param, Request, Response, UseGuards } from '@nestjs/common';
import { PdfService } from './pdf.service';
import { JwtAuthGuard } from '../auth/auth.guard';
import { Response as ExpressResponse } from 'express';
import CustomRequest from 'src/app.customRequest';

@Controller('pdf')
export class PdfController {
  constructor(private readonly pdfService: PdfService) { }

  // @UseGuards(JwtAuthGuard)
  @Post('save')
  async savePdf(
    @Body('encodedPdf') encodedPdf: string,
    @Body('fileName') fileName: string,
    @Body("key") key: string,
    @Request() req: CustomRequest, @Response() res: ExpressResponse
  ) {
    const userId: any = req.user._id;
    const savedPdf = await this.pdfService.savePdf(encodedPdf, fileName, userId, key);
    if (!savedPdf.status) return res.status(500).json({ message: "Failed to upload PDF", status: false });
    return res.status(200).json({ message: "Upload Successfull", status: true });

  }

  // @UseGuards(JwtAuthGuard)
  @Post('get')
  async getPdf(@Request() req, @Response() res: ExpressResponse) {
    const userId = req.user._id;
    const pdfBuffer = await this.pdfService.getPdfData(userId, req.body.key as string);
    console.log(pdfBuffer)
    if (!pdfBuffer.status) {
      return res.status(404).json(pdfBuffer);
    }

    res.set({
      'Content-Type': 'application/pdf',
      'Content-Disposition': `attachment; filename="${pdfBuffer.message}.pdf"`,
    });

    return res.send(pdfBuffer.pdfBuffer);
  }


  @Post("key")
  async verifyKey(@Body("key") key: string, @Body("id") id: string, @Request() req, @Response() res: ExpressResponse) {
    const response = await this.pdfService.verifyKey(key, id)
    return res.status(response.status ? 200 : 401).json(response)
  }

  @Get("all")
  async getPDFs(@Request() req: CustomRequest, @Response() res: ExpressResponse) {
    const userId: any = req.user?._id;
    const response = await this.pdfService.getPDFS(userId as string)
    return res.status(response.status ? 200 : 500).json({ ...response, user: req.user });
  }

}
