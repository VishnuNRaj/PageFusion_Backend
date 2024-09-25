import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './users.schema';

@Injectable()
export class UsersService {
    constructor(@InjectModel(User.name) private userModel: Model<User>) { }

    async findOneByEmail(email: string): Promise<User | undefined> {
        return this.userModel.findOne({ email }).exec();
    }

    async create(user: Partial<User>): Promise<User> {
        const newUser = new this.userModel(user);
        return newUser.save();
    }

    async findOneById(id:string) {
        return await this.userModel.findById(id)
    }
}
