import { Pipe, PipeTransform } from '@angular/core';

interface PermissionInfo {
  displayText: string;
  cssClass: string;
  iconClass: string;
  tooltip: string;
}

@Pipe({
  name: 'permissionFormat'
})
export class PermissionFormatPipe implements PipeTransform {
  
  /**
   * Transforms a comma-separated permissions string into an array of PermissionInfo objects.
   * @param permissionsString - A string containing permissions in the format "ACTION:RESOURCE", separated by commas
   * @returns An array of PermissionInfo objects with display text, CSS class, icon class, and tooltip for each permission
   * 
   * @remarks
   * - Splits the input string by commas to get individual permissions
   * - For each permission, splits by colon to separate action and resource
   * - Formats the action and resource for display
   * - Determines appropriate CSS class and icon class based on the action
   */
  transform(permissionsString: string | null | undefined): PermissionInfo[] {
    if (!permissionsString) return [];
    
    return permissionsString.split(',').map(permission => {
      const [action, resource] = permission.split(':');
      const formattedAction = action.charAt(0) + action.slice(1).toLowerCase();
      const formattedResource = resource.charAt(0) + resource.slice(1).toLowerCase();
      
      return {
        displayText: `${formattedAction} ${formattedResource}`,
        cssClass: this.getPermissionClass(action),
        iconClass: this.getPermissionIcon(action),
        tooltip: permission
      };
    });
  }

  /** Returns the CSS class for a given permission action 
   * @param action - The action part of the permission (e.g., "READ", "CREATE")
   * @returns A string representing the CSS class for styling
  */
  private getPermissionClass(action: string): string {
    switch (action) {
      case 'READ': return 'permission-read';
      case 'CREATE': return 'permission-create';
      case 'UPDATE': return 'permission-update';
      case 'DELETE': return 'permission-delete';
      default: return 'permission-default';
    }
  }

  /**
   * Returns the icon class for a given permission action
   * @param action - The action part of the permission (e.g., "READ", "CREATE")
   * @returns A string representing the icon class for display
   */
  private getPermissionIcon(action: string): string {
    switch (action) {
      case 'READ': return 'bi bi-eye';
      case 'CREATE': return 'bi bi-plus-circle';
      case 'UPDATE': return 'bi bi-pencil-square';
      case 'DELETE': return 'bi bi-trash';
      default: return 'bi bi-key';
    }
  }
}