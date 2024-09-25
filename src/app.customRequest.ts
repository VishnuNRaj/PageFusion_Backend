import { Request } from "express";
import { User } from "./users/users.schema";

export default interface CustomRequest extends Request {
    user?:User;
}