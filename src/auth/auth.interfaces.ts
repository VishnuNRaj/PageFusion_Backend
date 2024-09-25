export interface LoginRequest {
    email:string;
    password:string;
    remember:boolean;
}

export interface LoginResponse {
    accessToken?:string;
    refreshToken?:string;
    status:boolean;
    message:String;
}

export interface SignupResponse {
    message:String;
    status:boolean;
}

