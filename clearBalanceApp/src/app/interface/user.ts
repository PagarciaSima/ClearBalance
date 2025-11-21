/**
 * Interface representing a user.
 */
export interface User {
    id: number;
    firstName: string;
    lastName: string;
    email: string;
    address?: string;
    phone?: string;
    title?: string;
    bio?: string;
    imageUrl?: string;
    enabled: boolean;
    notLocked: boolean;
    usingMfa: boolean;
    createdAt?: Date | string;
    roleName: string;
    permissions: string;
}

