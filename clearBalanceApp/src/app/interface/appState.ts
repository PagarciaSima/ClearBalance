import { DataState } from "../enum/datastate.enum";

/**
 * AppState interface representing the state of the login process.
 */
export interface LoginState {
    dataState: DataState;
    loginSuccess?: boolean;
    error?: string;
    message?: string;
    usingMfa?: boolean;
    phone?: string;
}