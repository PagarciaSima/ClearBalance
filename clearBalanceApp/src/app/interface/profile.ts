import { Events } from "./events";
import { Role } from "./role";
import { User } from "./user";

export interface Profile {
    user: User;
    access_token?: string;
    refresh_token?: string;
    events?: Events[];
    roles?: Role[];
}