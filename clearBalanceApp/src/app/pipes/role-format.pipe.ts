import { Pipe, PipeTransform } from '@angular/core';

@Pipe({
  name: 'roleFormat'
})
export class RoleFormatPipe implements PipeTransform {
  
  /**
   * Transforms a role name string by removing the "ROLE_" prefix and formatting it for display.
   * @param roleName - The role name string to be transformed (e.g., "ROLE_SYSADMIN")
   * @returns A formatted role name string (e.g., "Sysadmin")
   * 
   * @remarks
   * - Checks if the input string is null or undefined and returns an empty string in that case
   * - Removes the "ROLE_" prefix if present
   * - Converts the remaining string to a more readable format by capitalizing the first letter and making the rest lowercase
   */
  transform(roleName: string | null | undefined): string {
    if (!roleName) return '';
    
    // Removes "ROLE_" prefix if present
    const nameWithoutPrefix = roleName.replace('ROLE_', '');
    
    // Converts to readable format: "SYSADMIN" -> "Sysadmin"
    return nameWithoutPrefix.charAt(0) + nameWithoutPrefix.slice(1).toLowerCase();
  }
}