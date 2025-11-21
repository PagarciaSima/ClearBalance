/**
 * Generic interface for custom HTTP responses.
 */
export interface CustomHttpResponse<T> {
    timestamp: Date;
    statusCode: number;
    status: string;
    reason?: string;
    message: string;
    developerMessage?: string;
    data?: T;
}
