"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
// dep modules
var Notation = require("notation");
var enums_1 = require("./enums");
var core_1 = require("./core");

var RESERVED_KEYWORDS = ['*', '!', '$', '$extend'];
exports.RESERVED_KEYWORDS = RESERVED_KEYWORDS;

var ERR_LOCK = 'Cannot alter the underlying grants model. AccessControl instance is locked.';
exports.ERR_LOCK = ERR_LOCK;
var utils = {
   
    type: function (o) {
        return Object.prototype.toString.call(o).match(/\s(\w+)/i)[1].toLowerCase();
    },
    
    hasDefined: function (o, propName) {
        return o.hasOwnProperty(propName) && o[propName] !== undefined;
    },
    
    toStringArray: function (value) {
        if (Array.isArray(value))
            return value;
        if (typeof value === 'string')
            return value.trim().split(/\s*[;,]\s*/);
        // throw new Error('Expected a string or array of strings, got ' + utils.type(value));
        return [];
    },
    
    isFilledStringArray: function (arr) {
        if (!arr || !Array.isArray(arr))
            return false;
        for (var _i = 0, arr_1 = arr; _i < arr_1.length; _i++) {
            var s = arr_1[_i];
            if (typeof s !== 'string' || s.trim() === '')
                return false;
        }
        return true;
    },
    
    isEmptyArray: function (value) {
        return Array.isArray(value) && value.length === 0;
    },
    
    pushUniq: function (arr, item) {
        if (arr.indexOf(item) < 0)
            arr.push(item);
        return arr;
    },
    
    uniqConcat: function (arrA, arrB) {
        var arr = arrA.concat();
        arrB.forEach(function (b) {
            utils.pushUniq(arr, b);
        });
        return arr;
    },
    
    subtractArray: function (arrA, arrB) {
        return arrA.concat().filter(function (a) { return arrB.indexOf(a) === -1; });
    },
    
    deepFreeze: function (o) {
       
        if (utils.type(o) !== 'object')
            return;
        var props = Object.getOwnPropertyNames(o);
        // freeze deeper before self
        props.forEach(function (key) {
            var sub = o[key];
            if (Array.isArray(sub))
                Object.freeze(sub);
            if (utils.type(sub) === 'object') {
                utils.deepFreeze(sub);
            }
        });
        // finally freeze self
        return Object.freeze(o);
    },
    
    each: function (array, callback, thisArg) {
        if (thisArg === void 0) { thisArg = null; }
        var length = array.length;
        var index = -1;
        while (++index < length) {
            if (callback.call(thisArg, array[index], index, array) === false)
                break;
        }
    },
    
    eachKey: function (object, callback, thisArg) {
        if (thisArg === void 0) { thisArg = null; }
       
        utils.each(Object.keys(object), callback, thisArg);
    },
   
    eachRole: function (grants, callback) {
        utils.eachKey(grants, function (name) { return callback(grants[name], name); });
    },
    
    eachRoleResource: function (grants, callback) {
        var resources, resourceDefinition;
        utils.eachKey(grants, function (role) {
            resources = grants[role];
            utils.eachKey(resources, function (resource) {
                resourceDefinition = role[resource];
                callback(role, resource, resourceDefinition);
            });
        });
    },
   
    isInfoFulfilled: function (info) {
        return utils.hasDefined(info, 'role')
            && utils.hasDefined(info, 'action')
            && utils.hasDefined(info, 'resource');
    },
   
    validName: function (name, throwOnInvalid) {
        if (throwOnInvalid === void 0) { throwOnInvalid = true; }
        if (typeof name !== 'string' || name.trim() === '') {
            if (!throwOnInvalid)
                return false;
            throw new core_1.AccessControlError('Invalid name, expected a valid string.');
        }
        if (RESERVED_KEYWORDS.indexOf(name) >= 0) {
            if (!throwOnInvalid)
                return false;
            throw new core_1.AccessControlError("Cannot use reserved name: \"" + name + "\"");
        }
        return true;
    },
   
    hasValidNames: function (list, throwOnInvalid) {
        if (throwOnInvalid === void 0) { throwOnInvalid = true; }
        var allValid = true;
        utils.each(utils.toStringArray(list), function (name) {
            if (!utils.validName(name, throwOnInvalid)) {
                allValid = false;
                return false; // break out of loop
            }
            // suppress tslint warning
            return true; // continue
        });
        return allValid;
    },
   
    validResourceObject: function (o) {
        if (utils.type(o) !== 'object') {
            throw new core_1.AccessControlError("Invalid resource definition.");
        }
        utils.eachKey(o, function (action) {
            var s = action.split(':');
            if (enums_1.actions.indexOf(s[0]) === -1) {
                throw new core_1.AccessControlError("Invalid action: \"" + action + "\"");
            }
            if (s[1] && enums_1.possessions.indexOf(s[1]) === -1) {
                throw new core_1.AccessControlError("Invalid action possession: \"" + action + "\"");
            }
            var perms = o[action];
            if (!utils.isEmptyArray(perms) && !utils.isFilledStringArray(perms)) {
                throw new core_1.AccessControlError("Invalid resource attributes for action \"" + action + "\".");
            }
        });
        return true;
    },
    
    validRoleObject: function (grants, roleName) {
        var role = grants[roleName];
        if (!role || utils.type(role) !== 'object') {
            throw new core_1.AccessControlError("Invalid role definition.");
        }
        utils.eachKey(role, function (resourceName) {
            if (!utils.validName(resourceName, false)) {
                if (resourceName === '$extend') {
                    var extRoles = role[resourceName]; // semantics
                    if (!utils.isFilledStringArray(extRoles)) {
                        throw new core_1.AccessControlError("Invalid extend value for role \"" + roleName + "\": " + JSON.stringify(extRoles));
                    }
                    else {
                        // attempt to actually extend the roles. this will throw
                        // on failure.
                        utils.extendRole(grants, roleName, extRoles);
                    }
                }
                else {
                    throw new core_1.AccessControlError("Cannot use reserved name \"" + resourceName + "\" for a resource.");
                }
            }
            else {
                utils.validResourceObject(role[resourceName]); // throws on failure
            }
        });
        return true;
    },
   
    getInspectedGrants: function (o) {
        var grants = {};
        var strErr = 'Invalid grants object.';
        var type = utils.type(o);
        if (type === 'object') {
            utils.eachKey(o, function (roleName) {
                if (utils.validName(roleName)) {
                    return utils.validRoleObject(o, roleName); // throws on failure
                }
                /* istanbul ignore next */
                return false;
                // above is redundant, previous checks will already throw on
                // failure so we'll never need to break early from this.
            });
            grants = o;
        }
        else if (type === 'array') {
            o.forEach(function (item) { return utils.commitToGrants(grants, item, true); });
        }
        else {
            throw new core_1.AccessControlError(strErr + " Expected an array or object.");
        }
        return grants;
    },
    
    getResources: function (grants) {
        // using an object for unique list
        var resources = {};
        utils.eachRoleResource(grants, function (role, resource, permissions) {
            resources[resource] = null;
        });
        return Object.keys(resources);
    },
   
    normalizeActionPossession: function (info, asString) {
        if (asString === void 0) { asString = false; }
        // validate and normalize action
        if (typeof info.action !== 'string') {
            // throw new AccessControlError(`Invalid action: ${info.action}`);
            throw new core_1.AccessControlError("Invalid action: " + JSON.stringify(info));
        }
        var s = info.action.split(':');
        if (enums_1.actions.indexOf(s[0].trim().toLowerCase()) < 0) {
            throw new core_1.AccessControlError("Invalid action: " + s[0]);
        }
        info.action = s[0].trim().toLowerCase();
        // validate and normalize possession
        var poss = info.possession || s[1];
        if (poss) {
            if (enums_1.possessions.indexOf(poss.trim().toLowerCase()) < 0) {
                throw new core_1.AccessControlError("Invalid action possession: " + poss);
            }
            else {
                info.possession = poss.trim().toLowerCase();
            }
        }
        else {
            // if no possession is set, we'll default to "any".
            info.possession = enums_1.Possession.ANY;
        }
        return asString
            ? info.action + ':' + info.possession
            : info;
    },
   
    normalizeQueryInfo: function (query) {
        if (utils.type(query) !== 'object') {
            throw new core_1.AccessControlError("Invalid IQueryInfo: " + typeof query);
        }
        // clone the object
        query = Object.assign({}, query);
        // validate and normalize role(s)
        query.role = utils.toStringArray(query.role);
        if (!utils.isFilledStringArray(query.role)) {
            throw new core_1.AccessControlError("Invalid role(s): " + JSON.stringify(query.role));
        }
        // validate resource
        if (typeof query.resource !== 'string' || query.resource.trim() === '') {
            throw new core_1.AccessControlError("Invalid resource: \"" + query.resource + "\"");
        }
        query.resource = query.resource.trim();
        query = utils.normalizeActionPossession(query);
        return query;
    },
   
    normalizeAccessInfo: function (access, all) {
        if (all === void 0) { all = false; }
        if (utils.type(access) !== 'object') {
            throw new core_1.AccessControlError("Invalid IAccessInfo: " + typeof access);
        }
        // clone the object
        access = Object.assign({}, access);
        // validate and normalize role(s)
        access.role = utils.toStringArray(access.role);
        if (access.role.length === 0 || !utils.isFilledStringArray(access.role)) {
            throw new core_1.AccessControlError("Invalid role(s): " + JSON.stringify(access.role));
        }
        // validate and normalize resource
        access.resource = utils.toStringArray(access.resource);
        if (access.resource.length === 0 || !utils.isFilledStringArray(access.resource)) {
            throw new core_1.AccessControlError("Invalid resource(s): " + JSON.stringify(access.resource));
        }
        // normalize attributes
        if (access.denied || (Array.isArray(access.attributes) && access.attributes.length === 0)) {
            access.attributes = [];
        }
        else {
            // if omitted and not denied, all attributes are allowed
            access.attributes = !access.attributes ? ['*'] : utils.toStringArray(access.attributes);
        }
        // this part is not necessary if this is invoked from a comitter method
        // such as `createAny()`. So we'll check if we need to validate all
        // properties such as `action` and `possession`.
        if (all)
            access = utils.normalizeActionPossession(access);
        return access;
    },
    
    resetAttributes: function (access) {
        if (access.denied) {
            access.attributes = [];
            return access;
        }
        if (!access.attributes || utils.isEmptyArray(access.attributes)) {
            access.attributes = ['*'];
        }
        return access;
    },
    
    getRoleHierarchyOf: function (grants, roleName, rootRole) {
       
        var role = grants[roleName];
        if (!role)
            throw new core_1.AccessControlError("Role not found: \"" + roleName + "\"");
        var arr = [roleName];
        if (!Array.isArray(role.$extend) || role.$extend.length === 0)
            return arr;
        role.$extend.forEach(function (exRoleName) {
            if (!grants[exRoleName]) {
                throw new core_1.AccessControlError("Role not found: \"" + grants[exRoleName] + "\"");
            }
            if (exRoleName === roleName) {
                throw new core_1.AccessControlError("Cannot extend role \"" + roleName + "\" by itself.");
            }
            
            if (rootRole && (rootRole === exRoleName)) {
                throw new core_1.AccessControlError("Cross inheritance is not allowed. Role \"" + exRoleName + "\" already extends \"" + rootRole + "\".");
            }
            var ext = utils.getRoleHierarchyOf(grants, exRoleName, rootRole || roleName);
            arr = utils.uniqConcat(arr, ext);
        });
        return arr;
    },
    
    getFlatRoles: function (grants, roles) {
        var arrRoles = utils.toStringArray(roles);
        if (arrRoles.length === 0) {
            throw new core_1.AccessControlError("Invalid role(s): " + JSON.stringify(roles));
        }
        var arr = utils.uniqConcat([], arrRoles); // roles.concat();
        arrRoles.forEach(function (roleName) {
            arr = utils.uniqConcat(arr, utils.getRoleHierarchyOf(grants, roleName));
        });
        // console.log(`flat roles for ${roles}`, arr);
        return arr;
    },
    
    getNonExistentRoles: function (grants, roles) {
        var non = [];
        if (utils.isEmptyArray(roles))
            return non;
        for (var _i = 0, roles_1 = roles; _i < roles_1.length; _i++) {
            var role = roles_1[_i];
            if (!grants.hasOwnProperty(role))
                non.push(role);
        }
        return non;
    },
    
    getCrossExtendingRole: function (grants, roleName, extenderRoles) {
        var extenders = utils.toStringArray(extenderRoles);
        var crossInherited = null;
        utils.each(extenders, function (e) {
            if (crossInherited || roleName === e) {
                return false; // break out of loop
            }
            var inheritedByExtender = utils.getRoleHierarchyOf(grants, e);
            utils.each(inheritedByExtender, function (r) {
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
   
    extendRole: function (grants, roles, extenderRoles) {
        // roles cannot be omitted or an empty array
        roles = utils.toStringArray(roles);
        if (roles.length === 0) {
            throw new core_1.AccessControlError("Invalid role(s): " + JSON.stringify(roles));
        }
        // extenderRoles cannot be omitted or but can be an empty array
        if (utils.isEmptyArray(extenderRoles))
            return;
        var arrExtRoles = utils.toStringArray(extenderRoles).concat();
        if (arrExtRoles.length === 0) {
            throw new core_1.AccessControlError("Cannot inherit invalid role(s): " + JSON.stringify(extenderRoles));
        }
        var nonExistentExtRoles = utils.getNonExistentRoles(grants, arrExtRoles);
        if (nonExistentExtRoles.length > 0) {
            throw new core_1.AccessControlError("Cannot inherit non-existent role(s): \"" + nonExistentExtRoles.join(', ') + "\"");
        }
        roles.forEach(function (roleName) {
            if (!grants[roleName])
                throw new core_1.AccessControlError("Role not found: \"" + roleName + "\"");
            if (arrExtRoles.indexOf(roleName) >= 0) {
                throw new core_1.AccessControlError("Cannot extend role \"" + roleName + "\" by itself.");
            }
            // getCrossExtendingRole() returns false or the first
            // cross-inherited role, if found.
            var crossInherited = utils.getCrossExtendingRole(grants, roleName, arrExtRoles);
            if (crossInherited) {
                throw new core_1.AccessControlError("Cross inheritance is not allowed. Role \"" + crossInherited + "\" already extends \"" + roleName + "\".");
            }
            utils.validName(roleName); // throws if false
            var r = grants[roleName];
            if (Array.isArray(r.$extend)) {
                r.$extend = utils.uniqConcat(r.$extend, arrExtRoles);
            }
            else {
                r.$extend = arrExtRoles;
            }
        });
    },
    
    preCreateRoles: function (grants, roles) {
        if (typeof roles === 'string')
            roles = utils.toStringArray(roles);
        if (!Array.isArray(roles) || roles.length === 0) {
            throw new core_1.AccessControlError("Invalid role(s): " + JSON.stringify(roles));
        }
        roles.forEach(function (role) {
            if (utils.validName(role) && !grants.hasOwnProperty(role)) {
                grants[role] = {};
            }
        });
    },
    
    commitToGrants: function (grants, access, normalizeAll) {
        if (normalizeAll === void 0) { normalizeAll = false; }
        access = utils.normalizeAccessInfo(access, normalizeAll);
        
        access.role.forEach(function (role) {
            if (utils.validName(role) && !grants.hasOwnProperty(role)) {
                grants[role] = {};
            }
            var grantItem = grants[role];
            var ap = access.action + ':' + access.possession;
            access.resource.forEach(function (res) {
                if (utils.validName(res) && !grantItem.hasOwnProperty(res)) {
                    grantItem[res] = {};
                }
               
                grantItem[res][ap] = utils.toStringArray(access.attributes);
            });
        });
    },
   
    getUnionAttrsOfRoles: function (grants, query) {
        // throws if has any invalid property value
        query = utils.normalizeQueryInfo(query);
        var role;
        var resource;
        var attrsList = [];
        // get roles and extended roles in a flat array
        var roles = utils.getFlatRoles(grants, query.role);
        // iterate through roles and add permission attributes (array) of
        // each role to attrsList (array).
        roles.forEach(function (roleName, index) {
            role = grants[roleName];
            // no need to check role existence #getFlatRoles() does that.
            resource = role[query.resource];
            if (resource) {
                // e.g. resource['create:own']
                // If action has possession "any", it will also return
                // `granted=true` for "own", if "own" is not defined.
                attrsList.push((resource[query.action + ':' + query.possession]
                    || resource[query.action + ':any']
                    || []).concat());
                // console.log(resource, 'for:', action + '.' + possession);
            }
        });
        // union all arrays of (permitted resource) attributes (for each role)
        // into a single array.
        var attrs = [];
        var len = attrsList.length;
        if (len > 0) {
            attrs = attrsList[0];
            var i = 1;
            while (i < len) {
                attrs = Notation.Glob.union(attrs, attrsList[i]);
                i++;
            }
        }
        return attrs;
    },
    
    lockAC: function (ac) {
        var _ac = ac; // ts
        if (!_ac._grants || Object.keys(_ac._grants).length === 0) {
            throw new core_1.AccessControlError('Cannot lock empty or invalid grants model.');
        }
        var locked = ac.isLocked && Object.isFrozen(_ac._grants);
        if (!locked)
            locked = Boolean(utils.deepFreeze(_ac._grants));
        /* istanbul ignore next */
        if (!locked) {
            throw new core_1.AccessControlError("Could not lock grants: " + typeof _ac._grants);
        }
        _ac._isLocked = locked;
    },
   
    filter: function (object, attributes) {
        if (!Array.isArray(attributes) || attributes.length === 0) {
            return {};
        }
        var notation = new Notation(object);
        return notation.filter(attributes).value;
    },
    
    filterAll: function (arrOrObj, attributes) {
        if (!Array.isArray(arrOrObj)) {
            return utils.filter(arrOrObj, attributes);
        }
        return arrOrObj.map(function (o) {
            return utils.filter(o, attributes);
        });
    }
};
exports.utils = utils;
