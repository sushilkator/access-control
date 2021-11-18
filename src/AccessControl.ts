import { Access, IAccessInfo, Query, IQueryInfo, Permission, AccessControlError } from './core';
import { Action, Possession, actions, possessions } from './enums';
import { utils, ERR_LOCK } from './utils';

class AccessControl {

    private _grants: any;

    
    private _isLocked: boolean = false;

    
    constructor(grants?: any) {
        // explicit undefined is not allowed
        if (arguments.length === 0) grants = {};
        this.setGrants(grants);
    }

    
    get isLocked(): boolean {
        return this._isLocked && Object.isFrozen(this._grants);
    }

    getGrants(): any {
        return this._grants;
    }

    
    setGrants(grantsObject: any): AccessControl {
        if (this.isLocked) throw new AccessControlError(ERR_LOCK);
        this._grants = utils.getInspectedGrants(grantsObject);
        return this;
    }

   
    reset(): AccessControl {
        if (this.isLocked) throw new AccessControlError(ERR_LOCK);
        this._grants = {};
        return this;
    }

    
    lock(): AccessControl {
        utils.lockAC(this);
        return this;
    }

   
    extendRole(roles: string | string[], extenderRoles: string | string[]): AccessControl {
        if (this.isLocked) throw new AccessControlError(ERR_LOCK);
        utils.extendRole(this._grants, roles, extenderRoles);
        return this;
    }

   
    removeRoles(roles: string | string[]): AccessControl {
        if (this.isLocked) throw new AccessControlError(ERR_LOCK);

        let rolesToRemove: string[] = utils.toStringArray(roles);
        if (rolesToRemove.length === 0 || !utils.isFilledStringArray(rolesToRemove)) {
            throw new AccessControlError(`Invalid role(s): ${JSON.stringify(roles)}`);
        }
        rolesToRemove.forEach((roleName: string) => {
            if (!this._grants[roleName]) {
                throw new AccessControlError(`Cannot remove a non-existing role: "${roleName}"`);
            }
            delete this._grants[roleName];
        });
        // also remove these roles from $extend list of each remaining role.
        utils.eachRole(this._grants, (roleItem: any, roleName: string) => {
            if (Array.isArray(roleItem.$extend)) {
                roleItem.$extend = utils.subtractArray(roleItem.$extend, rolesToRemove);
            }
        });
        return this;
    }

   
    removeResources(resources: string | string[], roles?: string | string[]): AccessControl {
        if (this.isLocked) throw new AccessControlError(ERR_LOCK);

       
        this._removePermission(resources, roles);
        return this;
    }

   
    getRoles(): string[] {
        return Object.keys(this._grants);
    }

   
    getInheritedRolesOf(role: string): string[] {
        let roles: string[] = utils.getRoleHierarchyOf(this._grants, role);
        roles.shift();
        return roles;
    }

    
    getExtendedRolesOf(role: string): string[] {
        return this.getInheritedRolesOf(role);
    }

  
    getResources(): string[] {
        return utils.getResources(this._grants);
    }

   
    hasRole(role: string | string[]): boolean {
        if (Array.isArray(role)) {
            return role.every((item: string) => this._grants.hasOwnProperty(item));
        }
        return this._grants.hasOwnProperty(role);
    }

    
    hasResource(resource: string | string[]): boolean {
        let resources = this.getResources();
        if (Array.isArray(resource)) {
            return resource.every((item: string) => resources.indexOf(item) >= 0);
        }
        if (typeof resource !== 'string' || resource === '') return false;
        return resources.indexOf(resource) >= 0;
    }

    can(role: string | string[] | IQueryInfo): Query {
        // throw on explicit undefined
        if (arguments.length !== 0 && role === undefined) {
            throw new AccessControlError('Invalid role(s): undefined');
        }
        // other explicit invalid values will be checked in constructor.
        return new Query(this._grants, role);
    }

   
    query(role: string | string[] | IQueryInfo): Query {
        return this.can(role);
    }

    permission(queryInfo: IQueryInfo): Permission {
        return new Permission(this._grants, queryInfo);
    }

    
    grant(role?: string | string[] | IAccessInfo): Access {
        if (this.isLocked) throw new AccessControlError(ERR_LOCK);
        // throw on explicit undefined
        if (arguments.length !== 0 && role === undefined) {
            throw new AccessControlError('Invalid role(s): undefined');
        }
        // other explicit invalid values will be checked in constructor.
        return new Access(this, role, false);
    }

   
    allow(role?: string | string[] | IAccessInfo): Access {
        return this.grant(role);
    }

    deny(role?: string | string[] | IAccessInfo): Access {
        if (this.isLocked) throw new AccessControlError(ERR_LOCK);
        // throw on explicit undefined
        if (arguments.length !== 0 && role === undefined) {
            throw new AccessControlError('Invalid role(s): undefined');
        }
        // other explicit invalid values will be checked in constructor.
        return new Access(this, role, true);
    }

   
    reject(role?: string | string[] | IAccessInfo): Access {
        return this.deny(role);
    }

    
    _removePermission(resources: string | string[], roles?: string | string[], actionPossession?: string) {
        resources = utils.toStringArray(resources);
        // resources is set but returns empty array.
        if (resources.length === 0 || !utils.isFilledStringArray(resources)) {
            throw new AccessControlError(`Invalid resource(s): ${JSON.stringify(resources)}`);
        }

        if (roles !== undefined) {
            roles = utils.toStringArray(roles);
            // roles is set but returns empty array.
            if (roles.length === 0 || !utils.isFilledStringArray(roles)) {
                throw new AccessControlError(`Invalid role(s): ${JSON.stringify(roles)}`);
            }
        }
        utils.eachRoleResource(this._grants, (role: string, resource: string, permissions: any) => {
            if (resources.indexOf(resource) >= 0
                // roles is optional. so remove if role is not defined.
                // if defined, check if the current role is in the list.
                && (!roles || roles.indexOf(role) >= 0)) {
                if (actionPossession) {
                    // e.g. 'create' » 'create:any'
                    // to parse and normalize actionPossession string:
                    const ap: string = utils.normalizeActionPossession({ action: actionPossession }, true) as string;
                    // above will also validate the given actionPossession
                    delete this._grants[role][resource][ap];
                } else {
                    // this is used for AccessControl#removeResources().
                    delete this._grants[role][resource];
                }
            }
        });
    }

    
    static get Action(): any {
        return Action;
    }

    
    static get Possession(): any {
        return Possession;
    }

   
    static get Error(): any {
        return AccessControlError;
    }

    static filter(data: any, attributes: string[]): any {
        return utils.filterAll(data, attributes);
    }

    
    static isACError(object: any): boolean {
        return object instanceof AccessControlError;
    }

    
    static isAccessControlError(object: any): boolean {
        return AccessControl.isACError(object);
    }
}

export { AccessControl };
