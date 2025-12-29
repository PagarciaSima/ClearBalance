import { DataState } from "../enum/datastate.enum";

export interface ResetPasswordState {
  dataState: DataState;
  registerSuccess?: boolean;
  error?: string;
  message?: string | null;
}