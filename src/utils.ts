import * as Notation from 'notation';
import { AccessControl } from './';
import { Action, actions, Possession, possessions } from './enums';
import { IAccessInfo, IQueryInfo, AccessControlError } from './core';


const RESERVED_KEYWORDS = ['*', '!', '$', '$extend'];

const ERR_LOCK = 'Cannot alter the underlying grants model. AccessControl instance is locked.'

const utils = {

    type(o: any): string {
        return Object.prototype.toString.call(o).match(/\s(\w+)/i)[1].toLowerCase();
    },

    
    hasDefined(o: any, propName: string): boolean {
        return o.hasOwnProperty(propName) && o[propName] !== undefined;
    },

   
    toStringArray(value: any): string[] {
        if (Array.isArray(value)) return value;
        if (typeof value === 'string') return value.trim().split(/\s*[;,]\s*/);
        // throw new Error('Expected a string or array of strings, got ' + utils.type(value));
        return [];
    },

    
    isFilledStringArray(arr: any[]): boolean {
        if (!arr || !Array.isArray(arr)) return false;
        for (let s of arr) {
            if (typeof s !== 'string' || s.trim() === '') return false;
        }
        return true;
    },

    
    isEmptyArray(value: any): boolean {
        return Array.isArray(value) && value.length === 0;
    },

    
    pushUniq(arr: string[], item: string): string[] {
        if (arr.indexOf(item) < 0) arr.push(item);
        return arr;
    },

    
    uniqConcat(arrA: string[], arrB: string[]): string[] {
        const arr: string[] = arrA.concat();
        arrB.forEach((b: string) => {
            utils.pushUniq(arr, b);
        });
        return arr;
    },

    
    subtractArray(arrA: string[], arrB: string[]): string[] {
        return arrA.concat().filter(a => arrB.indexOf(a) === -1);
    },

    
    deepFreeze(o: any): any {
        
        if (utils.type(o) !== 'object') return;
        const props = Object.getOwnPropertyNames(o);
        
        props.forEach((key: string) => {
            let sub = o[key];
            if (Array.isArray(sub)) Object.freeze(sub);
            if (utils.type(sub) === 'object') {
                utils.deepFreeze(sub);
            }
        });
        
        return Object.freeze(o);
    },

    
    each(array, callback, thisArg = null) {
        const length = array.length;
        let index = -1;
        while (++index < length) {
            if (callback.call(thisArg, array[index], index, array) === false) break;
        }
    },

   
    eachKey(object, callback, thisArg = null) {
        
        utils.each(Object.keys(object), callback, thisArg);
    },

    
    eachRole(grants, callback: (role: any, roleName: string) => void) {
        utils.eachKey(grants, (name: string) => callback(grants[name], name));
    },

   
    eachRoleResource(grants, callback: (role: string, resource: string, resourceDefinition: any) => void) {
        let resources, resourceDefinition;
        utils.eachKey(grants, (role: string) => {
            resources = grants[role];
            utils.eachKey(resources, (resource: string) => {
                resourceDefinition = role[resource];
                callback(role, resource, resourceDefinition);
            });
        });
    },

    
    isInfoFulfilled(info: IAccessInfo | IQueryInfo): boolean {
        return utils.hasDefined(info, 'role')
            && utils.hasDefined(info, 'action')
            && utils.hasDefined(info, 'resource');
    },

    
    validName(name: string, throwOnInvalid: boolean = true): boolean {
        if (typeof name !== 'string' || name.trim() === '') {
            if (!throwOnInvalid) return false;
            throw new AccessControlError('Invalid name, expected a valid string.');
        }
        if (RESERVED_KEYWORDS.indexOf(name) >= 0) {
            if (!throwOnInvalid) return false;
            throw new AccessControlError(`Cannot use reserved name: "${name}"`);
        }
        return true;
    },

   
    hasValidNames(list: any, throwOnInvalid: boolean = true): boolean {
        let allValid = true;
        utils.each(utils.toStringArray(list), name => {
            if (!utils.validName(name, throwOnInvalid)) {
                allValid = false;
                return false; // break out of loop
            }
            // suppress tslint warning
            return true; // continue
        });
        return allValid;
    },

    
    validResourceObject(o: any): boolean {
        if (utils.type(o) !== 'object') {
            throw new AccessControlError(`Invalid resource definition.`);
        }

        utils.eachKey(o, action => {
            let s: string[] = action.split(':');
            if (actions.indexOf(s[0]) === -1) {
                throw new AccessControlError(`Invalid action: "${action}"`);
            }
            if (s[1] && possessions.indexOf(s[1]) === -1) {
                throw new AccessControlError(`Invalid action possession: "${action}"`);
            }
            let perms = o[action];
            if (!utils.isEmptyArray(perms) && !utils.isFilledStringArray(perms)) {
                throw new AccessControlError(`Invalid resource attributes for action "${action}".`);
            }
        });
        return true;
    },

    
    validRoleObject(grants: any, roleName: string): boolean {
        let role = grants[roleName];
        if (!role || utils.type(role) !== 'object') {
            throw new AccessControlError(`Invalid role definition.`);
        }

        utils.eachKey(role, (resourceName: string) => {
            if (!utils.validName(resourceName, false)) {
                if (resourceName === '$extend') {
                    let extRoles: string[] = role[resourceName]; // semantics
                    if (!utils.isFilledStringArray(extRoles)) {
                        throw new AccessControlError(`Invalid extend value for role "${roleName}": ${JSON.stringify(extRoles)}`);
                    } else {
                        // attempt to actually extend the roles. this will throw
                        // on failure.
                        utils.extendRole(grants, roleName, extRoles);
                    }
                } else {
                    throw new AccessControlError(`Cannot use reserved name "${resourceName}" for a resource.`);
                }
            } else {
                utils.validResourceObject(role[resourceName]); // throws on failure
            }
        });
        return true;
    },

   
    getInspectedGrants(o: any): any {
        let grants = {};
        const strErr: string = 'Invalid grants object.';
        const type: string = utils.type(o);

        if (type === 'object') {
            utils.eachKey(o, (roleName: string) => {
                if (utils.validName(roleName)) { // throws on failure
                    return utils.validRoleObject(o, roleName); // throws on failure
                }
                
                return false;
                
            });
            grants = o;
        } else if (type === 'array') {
            o.forEach((item: any) => utils.commitToGrants(grants, item, true));
        } else {
            throw new AccessControlError(`${strErr} Expected an array or object.`);
        }

        return grants;
    },

    
    getResources(grants: any): string[] {
        // using an object for unique list
        let resources: any = {};
        utils.eachRoleResource(grants, (role: string, resource: string, permissions: any) => {
            resources[resource] = null;
        });
        return Object.keys(resources);
    },

    
    normalizeActionPossession(info: IQueryInfo | IAccessInfo, asString: boolean = false): IQueryInfo | IAccessInfo | string {
        if (typeof info.action !== 'string') {
            throw new AccessControlError(`Invalid action: ${JSON.stringify(info)}`);
        }

        const s: string[] = info.action.split(':');
        if (actions.indexOf(s[0].trim().toLowerCase()) < 0) {
            throw new AccessControlError(`Invalid action: ${s[0]}`);
        }
        info.action = s[0].trim().toLowerCase();

        const poss: string = info.possession || s[1];
        if (poss) {
            if (possessions.indexOf(poss.trim().toLowerCase()) < 0) {
                throw new AccessControlError(`Invalid action possession: ${poss}`);
            } else {
                info.possession = poss.trim().toLowerCase();
            }
        } else {
            info.possession = Possession.ANY;
        }

        return asString
            ? info.action + ':' + info.possession
            : info;
    },

    
    normalizeQueryInfo(query: IQueryInfo): IQueryInfo {
        if (utils.type(query) !== 'object') {
            throw new AccessControlError(`Invalid IQueryInfo: ${typeof query}`);
        }
        // clone the object
        query = Object.assign({}, query);
        // validate and normalize role(s)
        query.role = utils.toStringArray(query.role);
        if (!utils.isFilledStringArray(query.role)) {
            throw new AccessControlError(`Invalid role(s): ${JSON.stringify(query.role)}`);
        }

        // validate resource
        if (typeof query.resource !== 'string' || query.resource.trim() === '') {
            throw new AccessControlError(`Invalid resource: "${query.resource}"`);
        }
        query.resource = query.resource.trim();
        query = utils.normalizeActionPossession(query) as IQueryInfo;

        return query;
    },

    
    normalizeAccessInfo(access: IAccessInfo, all: boolean = false): IAccessInfo {
        if (utils.type(access) !== 'object') {
            throw new AccessControlError(`Invalid IAccessInfo: ${typeof access}`);
        }
        // clone the object
        access = Object.assign({}, access);
        // validate and normalize role(s)
        access.role = utils.toStringArray(access.role);
        if (access.role.length === 0 || !utils.isFilledStringArray(access.role)) {
            throw new AccessControlError(`Invalid role(s): ${JSON.stringify(access.role)}`);
        }

        // validate and normalize resource
        access.resource = utils.toStringArray(access.resource);
        if (access.resource.length === 0 || !utils.isFilledStringArray(access.resource)) {
            throw new AccessControlError(`Invalid resource(s): ${JSON.stringify(access.resource)}`);
        }

        // normalize attributes
        if (access.denied || (Array.isArray(access.attributes) && access.attributes.length === 0)) {
            access.attributes = [];
        } else {
            // if omitted and not denied, all attributes are allowed
            access.attributes = !access.attributes ? ['*'] : utils.toStringArray(access.attributes);
        }

       
        if (all) access = utils.normalizeActionPossession(access) as IAccessInfo;

        return access;
    },

    
    resetAttributes(access: IAccessInfo): IAccessInfo {
        if (access.denied) {
            access.attributes = [];
            return access;
        }
        if (!access.attributes || utils.isEmptyArray(access.attributes)) {
            access.attributes = ['*'];
        }
        return access;
    },

   
    getRoleHierarchyOf(grants: any, roleName: string, rootRole?: string): string[] {
       
        const role: any = grants[roleName];
        if (!role) throw new AccessControlError(`Role not found: "${roleName}"`);

        let arr: string[] = [roleName];
        if (!Array.isArray(role.$extend) || role.$extend.length === 0) return arr;

        role.$extend.forEach((exRoleName: string) => {
            if (!grants[exRoleName]) {
                throw new AccessControlError(`Role not found: "${grants[exRoleName]}"`);
            }
            if (exRoleName === roleName) {
                throw new AccessControlError(`Cannot extend role "${roleName}" by itself.`);
            }
            
            if (rootRole && (rootRole === exRoleName)) {
                throw new AccessControlError(`Cross inheritance is not allowed. Role "${exRoleName}" already extends "${rootRole}".`);
            }
            let ext: string[] = utils.getRoleHierarchyOf(grants, exRoleName, rootRole || roleName);
            arr = utils.uniqConcat(arr, ext);
        });
        return arr;
    },

    
    getFlatRoles(grants: any, roles: string | string[]): string[] {
        const arrRoles: string[] = utils.toStringArray(roles);
        if (arrRoles.length === 0) {
            throw new AccessControlError(`Invalid role(s): ${JSON.stringify(roles)}`);
        }
        let arr: string[] = utils.uniqConcat([], arrRoles); // roles.concat();
        arrRoles.forEach((roleName: string) => {
            arr = utils.uniqConcat(arr, utils.getRoleHierarchyOf(grants, roleName));
        });
        // console.log(`flat roles for ${roles}`, arr);
        return arr;
    },

    
    getNonExistentRoles(grants: any, roles: string[]) {
        let non: string[] = [];
        if (utils.isEmptyArray(roles)) return non;
        for (let role of roles) {
            if (!grants.hasOwnProperty(role)) non.push(role);
        }
        return non;
    },

    getCrossExtendingRole(grants: any, roleName: string, extenderRoles: string | string[]): string {
        const extenders: string[] = utils.toStringArray(extenderRoles);
        let crossInherited: any = null;
        utils.each(extenders, (e: string) => {
            if (crossInherited || roleName === e) {
                return false; // break out of loop
            }
            const inheritedByExtender = utils.getRoleHierarchyOf(grants, e);
            utils.each(inheritedByExtender, (r: string) => {
                if (r === roleName) {
                    // get/report the parent role
                    crossInherited = e;
                    return false; // break out of loop
                }
                // suppress tslint warning
                return true; // continue
            });
            // suppress tslint warning
            return true; // continue
        });
        return crossInherited;
    },

    
    extendRole(grants: any, roles: string | string[], extenderRoles: string | string[]) {
        // roles cannot be omitted or an empty array
        roles = utils.toStringArray(roles);
        if (roles.length === 0) {
            throw new AccessControlError(`Invalid role(s): ${JSON.stringify(roles)}`);
        }

        // extenderRoles cannot be omitted or but can be an empty array
        if (utils.isEmptyArray(extenderRoles)) return;

        const arrExtRoles: string[] = utils.toStringArray(extenderRoles).concat();
        if (arrExtRoles.length === 0) {
            throw new AccessControlError(`Cannot inherit invalid role(s): ${JSON.stringify(extenderRoles)}`);
        }

        const nonExistentExtRoles: string[] = utils.getNonExistentRoles(grants, arrExtRoles);
        if (nonExistentExtRoles.length > 0) {
            throw new AccessControlError(`Cannot inherit non-existent role(s): "${nonExistentExtRoles.join(', ')}"`);
        }

        roles.forEach((roleName: string) => {
            if (!grants[roleName]) throw new AccessControlError(`Role not found: "${roleName}"`);

            if (arrExtRoles.indexOf(roleName) >= 0) {
                throw new AccessControlError(`Cannot extend role "${roleName}" by itself.`);
            }

            // getCrossExtendingRole() returns false or the first
            // cross-inherited role, if found.
            let crossInherited: string = utils.getCrossExtendingRole(grants, roleName, arrExtRoles);
            if (crossInherited) {
                throw new AccessControlError(`Cross inheritance is not allowed. Role "${crossInherited}" already extends "${roleName}".`);
            }

            utils.validName(roleName); // throws if false
            let r = grants[roleName];
            if (Array.isArray(r.$extend)) {
                r.$extend = utils.uniqConcat(r.$extend, arrExtRoles);
            } else {
                r.$extend = arrExtRoles;
            }
        });
    },

    
    preCreateRoles(grants: any, roles: string | string[]) {
        if (typeof roles === 'string') roles = utils.toStringArray(roles);
        if (!Array.isArray(roles) || roles.length === 0) {
            throw new AccessControlError(`Invalid role(s): ${JSON.stringify(roles)}`);
        }
        (roles as string[]).forEach((role: string) => {
            if (utils.validName(role) && !grants.hasOwnProperty(role)) {
                grants[role] = {};
            }
        });
    },

    commitToGrants(grants: any, access: IAccessInfo, normalizeAll: boolean = false) {
        access = utils.normalizeAccessInfo(access, normalizeAll);
       
        (access.role as string[]).forEach((role: string) => {
            if (utils.validName(role) && !grants.hasOwnProperty(role)) {
                grants[role] = {};
            }

            let grantItem: any = grants[role];
            let ap: string = access.action + ':' + access.possession;
            (access.resource as string[]).forEach((res: string) => {
                if (utils.validName(res) && !grantItem.hasOwnProperty(res)) {
                    grantItem[res] = {};
                }
                
                grantItem[res][ap] = utils.toStringArray(access.attributes);
            });
        });
    },

    getUnionAttrsOfRoles(grants: any, query: IQueryInfo): string[] {
        // throws if has any invalid property value
        query = utils.normalizeQueryInfo(query);

        let role;
        let resource: string;
        let attrsList: Array<string[]> = [];
        // get roles and extended roles in a flat array
        const roles: string[] = utils.getFlatRoles(grants, query.role);
        
        roles.forEach((roleName: string, index: number) => {
            role = grants[roleName];

            resource = role[query.resource];
            if (resource) {
               
                attrsList.push(
                    (resource[query.action + ':' + query.possession]
                        || resource[query.action + ':any']
                        || []).concat()
                );
            }
        });

        let attrs = [];
        const len: number = attrsList.length;
        if (len > 0) {
            attrs = attrsList[0];
            let i = 1;
            while (i < len) {
                attrs = Notation.Glob.union(attrs, attrsList[i]);
                i++;
            }
        }
        return attrs;
    },

    
    lockAC(ac: AccessControl) {
        const _ac = ac as any; // ts
        if (!_ac._grants || Object.keys(_ac._grants).length === 0) {
            throw new AccessControlError('Cannot lock empty or invalid grants model.');
        }

        let locked = ac.isLocked && Object.isFrozen(_ac._grants);
        if (!locked) locked = Boolean(utils.deepFreeze(_ac._grants));

        if (!locked) {
            throw new AccessControlError(`Could not lock grants: ${typeof _ac._grants}`);
        }

        _ac._isLocked = locked;
    },

    
    filter(object: any, attributes: string[]): any {
        if (!Array.isArray(attributes) || attributes.length === 0) {
            return {};
        }
        const notation = new Notation(object);
        return notation.filter(attributes).value;
    },

    
    filterAll(arrOrObj: any, attributes: string[]): any {
        if (!Array.isArray(arrOrObj)) {
            return utils.filter(arrOrObj, attributes);
        }
        return arrOrObj.map(o => {
            return utils.filter(o, attributes);
        });
    }

};

export {
    utils,
    RESERVED_KEYWORDS,
    ERR_LOCK
};
