import { Access, IAccessInfo, Query, IQueryInfo, Permission } from './core';
declare class AccessControl {
    
    private _grants;
    
    private _isLocked;
    
    constructor(grants?: any);
   
    readonly isLocked: boolean;
    getGrants(): any;
     setGrants(grantsObject: any): AccessControl;
    
    reset(): AccessControl;
    
    lock(): AccessControl;
    
    extendRole(roles: string | string[], extenderRoles: string | string[]): AccessControl;
    
    removeRoles(roles: string | string[]): AccessControl;
    
    removeResources(resources: string | string[], roles?: string | string[]): AccessControl;
   
    getRoles(): string[];
    
    getInheritedRolesOf(role: string): string[];
    
    getExtendedRolesOf(role: string): string[];
    
    getResources(): string[];
    
    hasRole(role: string | string[]): boolean;
   
    hasResource(resource: string | string[]): boolean;
    
    can(role: string | string[] | IQueryInfo): Query;
   
    query(role: string | string[] | IQueryInfo): Query;
   
    permission(queryInfo: IQueryInfo): Permission;
    grant(role?: string | string[] | IAccessInfo): Access;
    
    allow(role?: string | string[] | IAccessInfo): Access;
    
    deny(role?: string | string[] | IAccessInfo): Access;
    
    reject(role?: string | string[] | IAccessInfo): Access;
    
    _removePermission(resources: string | string[], roles?: string | string[], actionPossession?: string): void;
    
    static readonly Action: any;
    
    static readonly Possession: any;
    
    static readonly Error: any;
    
    static filter(data: any, attributes: string[]): any;
    
    static isACError(object: any): boolean;
    
    static isAccessControlError(object: any): boolean;
}
export { AccessControl };
