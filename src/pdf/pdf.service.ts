// import { Injectable } from '@nestjs/common';
// import * as fs from 'fs';
// import { join } from 'path';
// import * as crypto from 'crypto';
// import { InjectModel } from '@nestjs/mongoose';
// import { Model } from 'mongoose';
// import { compare, hash } from 'bcryptjs';
// import { Pdf } from './pdf.schema';
// import { JwtService } from '@nestjs/jwt';

// @Injectable()
// export class PdfService {
//     constructor(@InjectModel(Pdf.name) private pdfModel: Model<Pdf>, private jwtService: JwtService) { }

//     private generateKey(key: string): Buffer {
//         return crypto.createHash('sha256').update(key).digest();
//     }

//     private encrypt(buffer: string, key: string): { iv: Buffer; encryptedData: Buffer } {
//         const iv = crypto.randomBytes(16);
//         const cipherKey = this.generateKey(key);
//         const cipher = crypto.createCipheriv('aes-256-cbc', cipherKey, iv);
//         let encrypted = cipher.update(buffer, 'base64'); // Assuming buffer is base64
//         encrypted = Buffer.concat([encrypted, cipher.final()]);
//         return { iv, encryptedData: encrypted };
//     }

//     private decrypt(buffer: Buffer, key: string, iv: Buffer): Buffer {
//         const decipherKey = this.generateKey(key);
//         const decipher = crypto.createDecipheriv('aes-256-cbc', decipherKey, iv);
//         let decrypted = decipher.update(buffer);
//         decrypted = Buffer.concat([decrypted, decipher.final()]);
//         return decrypted;
//     }

//     async savePdf(encodedPdf: string, fileName: string, userId: string, key: string): Promise<{ status: boolean; message: string }> {
//         try {
//             const { iv, encryptedData } = this.encrypt(encodedPdf, key);

//             const folderPath = join(__dirname, '../../files', userId.toString());
//             if (!fs.existsSync(folderPath)) {
//                 fs.mkdirSync(folderPath, { recursive: true });
//             }

//             const filePath = join(folderPath, `${fileName}-${Date.now()}.enc`);
//             const fileContent = Buffer.concat([iv, encryptedData]);
//             fs.writeFileSync(filePath, fileContent);

//             const hashedKey = await hash(key, 10);
//             const pdf = new this.pdfModel({
//                 userId,
//                 fileName,
//                 filePath,
//                 key: hashedKey,
//             });

//             await pdf.save();
//             return { status: true, message: "PDF saved successfully" };
//         } catch (error) {
//             console.error("Error saving PDF:", error);
//             return { status: false, message: "Error saving PDF" };
//         }
//     }


//     async getPdfData(userId: string, decode: string): Promise<{ decryptedBuffer?: Buffer; status: boolean; message: string }> {
//         try {
//             const { id, key, name } = await this.jwtService.verify(decode) as { key: string; id: string; name: string };
//             const pdf = await this.pdfModel.findOne({ _id: id, userId });

//             if (!pdf) {
//                 return { status: false, message: "PDF not found" };
//             }

//             if (!await compare(key, pdf.key)) {
//                 return { status: false, message: "Invalid key" };
//             }
//             console.log(pdf)
//             const filePath = pdf.filePath;
//             if (!fs.existsSync(filePath)) {
//                 return { status: false, message: "File not found" };
//             }
//             const fileContent = fs.readFileSync(filePath);

//             const iv = fileContent.slice(0, 16);
//             const encryptedData = fileContent.slice(16);

//             const decryptedBuffer = this.decrypt(encryptedData, key, iv);
//             return { decryptedBuffer, status: true, message: `PDF retrieved successfully: ${name}` };
//         } catch (error) {
//             console.error("Error retrieving PDF:", error);
//             return { status: false, message: "Error retrieving PDF" };
//         }
//     }

//     async verifyKey(key: string, id: string): Promise<{ key?: string; status: boolean; message: string }> {
//         try {
//             const pdf = await this.pdfModel.findById(id);
//             if (!pdf) return { status: false, message: "No PDF found" };

//             if (!await compare(key, pdf.key)) return { status: false, message: "Incorrect key" };

//             return { status: true, message: "Key verified", key: this.jwtService.sign({ key, id: pdf._id, name: pdf.fileName }, { expiresIn: "10m" }) };
//         } catch (error) {
//             console.error("Error verifying key:", error);
//             return { status: false, message: "Internal server error" };
//         }
//     }

//     async getPDFS(userId: string): Promise<{ status: boolean; message: string; pdfs: Pdf[] }> {
//         try {
//             const response = await this.pdfModel.find({ userId }, { _id: 1, fileName: 1 });
//             return { status: true, message: "Found", pdfs: response };
//         } catch (error) {
//             console.error("Error fetching PDFs:", error);
//             return { status: false, message: "Internal server error", pdfs: [] };
//         }
//     }
// }


import { Injectable } from '@nestjs/common';
import * as fs from 'fs';
import { join } from 'path';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { compare, hash } from 'bcryptjs';
import { Pdf } from './pdf.schema';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class PdfService {
    constructor(
        @InjectModel(Pdf.name) private pdfModel: Model<Pdf>,
        private jwtService: JwtService
    ) { }

    async savePdf(
        encodedPdf: string,
        fileName: string,
        userId: string,
        key: string
    ): Promise<{ status: boolean; message: string }> {
        try {
            const folderPath = join(__dirname, '../../files', userId.toString());
            if (!fs.existsSync(folderPath)) {
                fs.mkdirSync(folderPath, { recursive: true });
            }

            const buffer = Buffer.from(encodedPdf.split(',')[1], 'base64');
            const filePath = join(folderPath, `${fileName}-${new Date().toISOString()}.txt`);
            fs.writeFileSync(filePath, buffer);

            const hashedKey = await hash(key, 10);
            const pdf = new this.pdfModel({
                userId,
                fileName,
                filePath,
                key: hashedKey,
            });

            await pdf.save();
            return { status: true, message: "PDF saved successfully" };
        } catch (error) {
            console.error("Error saving PDF:", error);
            return { status: false, message: "Error saving PDF" };
        }
    }

    async getPdfData(
        userId: string,
        decode: string
    ): Promise<{ pdfBuffer?: Buffer; status: boolean; message: string }> {
        try {
            const { id, key, name } = await this.jwtService.verify(decode) as { key: string; id: string; name: string };
            const pdf = await this.pdfModel.findOne({ _id: id, userId });

            if (!pdf) {
                return { status: false, message: "PDF not found" };
            }
            if (!await compare(key, pdf.key)) {
                return { status: false, message: "Invalid key" };
            }

            const filePath = pdf.filePath;
            if (!fs.existsSync(filePath)) {
                return { status: false, message: "File not found" };
            }

            const pdfBuffer = fs.readFileSync(filePath);

            return { pdfBuffer, status: true, message: `PDF retrieved successfully: ${name}` };
        } catch (error) {
            console.error("Error retrieving PDF:", error);
            return { status: false, message: "Error retrieving PDF" };
        }
    }

    async verifyKey(
        key: string,
        id: string
    ): Promise<{ key?: string; status: boolean; message: string }> {
        try {
            const pdf = await this.pdfModel.findById(id);
            if (!pdf) return { status: false, message: "No PDF found" };

            if (!await compare(key, pdf.key)) return { status: false, message: "Incorrect key" };
            return {
                status: true,
                message: "Key verified",
                key: this.jwtService.sign({ key, id: pdf._id, name: pdf.fileName }, { expiresIn: "10m" })
            };
        } catch (error) {
            console.error("Error verifying key:", error);
            return { status: false, message: "Internal server error" };
        }
    }

    async getPDFS(userId: string): Promise<{ status: boolean; message: string; pdfs: Pdf[] }> {
        try {
            const response = await this.pdfModel.find({ userId }, { _id: 1, fileName: 1 });
            return { status: true, message: "Found", pdfs: response };
        } catch (error) {
            console.error("Error fetching PDFs:", error);
            return { status: false, message: "Internal server error", pdfs: [] };
        }
    }
}
