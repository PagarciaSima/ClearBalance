import { DataState } from "../enum/datastate.enum";

export interface RegisterState {
  dataState: DataState;
  registerSuccess?: boolean;
  error?: string;
  message?: string | null;
}