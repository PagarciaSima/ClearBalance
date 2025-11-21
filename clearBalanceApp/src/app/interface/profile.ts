import { User } from "./user";

export interface Profile {
    user?: User;
    access_token: string;
    refresh_token: string;
}