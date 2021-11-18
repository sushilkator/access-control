"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var core_1 = require("./core");
var enums_1 = require("./enums");
var utils_1 = require("./utils");
var AccessControl = /** @class */ (function () {
    
    function AccessControl(grants) {
        
        this._isLocked = false;
        // explicit undefined is not allowed
        if (arguments.length === 0)
            grants = {};
        this.setGrants(grants);
    }
    Object.defineProperty(AccessControl.prototype, "isLocked", {
       
        get: function () {
            return this._isLocked && Object.isFrozen(this._grants);
        },
        enumerable: true,
        configurable: true
    });
    AccessControl.prototype.getGrants = function () {
        return this._grants;
    };
    
    AccessControl.prototype.setGrants = function (grantsObject) {
        if (this.isLocked)
            throw new core_1.AccessControlError(utils_1.ERR_LOCK);
        this._grants = utils_1.utils.getInspectedGrants(grantsObject);
        return this;
    };
    
    AccessControl.prototype.reset = function () {
        if (this.isLocked)
            throw new core_1.AccessControlError(utils_1.ERR_LOCK);
        this._grants = {};
        return this;
    };
    AccessControl.prototype.lock = function () {
        utils_1.utils.lockAC(this);
        return this;
    };
    
    AccessControl.prototype.extendRole = function (roles, extenderRoles) {
        if (this.isLocked)
            throw new core_1.AccessControlError(utils_1.ERR_LOCK);
        utils_1.utils.extendRole(this._grants, roles, extenderRoles);
        return this;
    };
   
    AccessControl.prototype.removeRoles = function (roles) {
        var _this = this;
        if (this.isLocked)
            throw new core_1.AccessControlError(utils_1.ERR_LOCK);
        var rolesToRemove = utils_1.utils.toStringArray(roles);
        if (rolesToRemove.length === 0 || !utils_1.utils.isFilledStringArray(rolesToRemove)) {
            throw new core_1.AccessControlError("Invalid role(s): " + JSON.stringify(roles));
        }
        rolesToRemove.forEach(function (roleName) {
            if (!_this._grants[roleName]) {
                throw new core_1.AccessControlError("Cannot remove a non-existing role: \"" + roleName + "\"");
            }
            delete _this._grants[roleName];
        });
        // also remove these roles from $extend list of each remaining role.
        utils_1.utils.eachRole(this._grants, function (roleItem, roleName) {
            if (Array.isArray(roleItem.$extend)) {
                roleItem.$extend = utils_1.utils.subtractArray(roleItem.$extend, rolesToRemove);
            }
        });
        return this;
    };
    
    AccessControl.prototype.removeResources = function (resources, roles) {
        if (this.isLocked)
            throw new core_1.AccessControlError(utils_1.ERR_LOCK);
        // _removePermission has a third argument `actionPossession`. if
        // omitted (like below), removes the parent resource object.
        this._removePermission(resources, roles);
        return this;
    };
    
    AccessControl.prototype.getRoles = function () {
        return Object.keys(this._grants);
    };
    
    AccessControl.prototype.getInheritedRolesOf = function (role) {
        var roles = utils_1.utils.getRoleHierarchyOf(this._grants, role);
        roles.shift();
        return roles;
    };
    
    AccessControl.prototype.getExtendedRolesOf = function (role) {
        return this.getInheritedRolesOf(role);
    };
    
    AccessControl.prototype.getResources = function () {
        return utils_1.utils.getResources(this._grants);
    };
    
    AccessControl.prototype.hasRole = function (role) {
        var _this = this;
        if (Array.isArray(role)) {
            return role.every(function (item) { return _this._grants.hasOwnProperty(item); });
        }
        return this._grants.hasOwnProperty(role);
    };
    
    AccessControl.prototype.hasResource = function (resource) {
        var resources = this.getResources();
        if (Array.isArray(resource)) {
            return resource.every(function (item) { return resources.indexOf(item) >= 0; });
        }
        if (typeof resource !== 'string' || resource === '')
            return false;
        return resources.indexOf(resource) >= 0;
    };
    
    AccessControl.prototype.can = function (role) {
        // throw on explicit undefined
        if (arguments.length !== 0 && role === undefined) {
            throw new core_1.AccessControlError('Invalid role(s): undefined');
        }
        // other explicit invalid values will be checked in constructor.
        return new core_1.Query(this._grants, role);
    };
   
    AccessControl.prototype.query = function (role) {
        return this.can(role);
    };
    
    AccessControl.prototype.permission = function (queryInfo) {
        return new core_1.Permission(this._grants, queryInfo);
    };
    
    AccessControl.prototype.grant = function (role) {
        if (this.isLocked)
            throw new core_1.AccessControlError(utils_1.ERR_LOCK);
        // throw on explicit undefined
        if (arguments.length !== 0 && role === undefined) {
            throw new core_1.AccessControlError('Invalid role(s): undefined');
        }
        // other explicit invalid values will be checked in constructor.
        return new core_1.Access(this, role, false);
    };
    
    AccessControl.prototype.allow = function (role) {
        return this.grant(role);
    };
    
    AccessControl.prototype.deny = function (role) {
        if (this.isLocked)
            throw new core_1.AccessControlError(utils_1.ERR_LOCK);
        // throw on explicit undefined
        if (arguments.length !== 0 && role === undefined) {
            throw new core_1.AccessControlError('Invalid role(s): undefined');
        }
        // other explicit invalid values will be checked in constructor.
        return new core_1.Access(this, role, true);
    };
    
    AccessControl.prototype.reject = function (role) {
        return this.deny(role);
    };
    
    AccessControl.prototype._removePermission = function (resources, roles, actionPossession) {
        var _this = this;
        resources = utils_1.utils.toStringArray(resources);
        // resources is set but returns empty array.
        if (resources.length === 0 || !utils_1.utils.isFilledStringArray(resources)) {
            throw new core_1.AccessControlError("Invalid resource(s): " + JSON.stringify(resources));
        }
        if (roles !== undefined) {
            roles = utils_1.utils.toStringArray(roles);
            // roles is set but returns empty array.
            if (roles.length === 0 || !utils_1.utils.isFilledStringArray(roles)) {
                throw new core_1.AccessControlError("Invalid role(s): " + JSON.stringify(roles));
            }
        }
        utils_1.utils.eachRoleResource(this._grants, function (role, resource, permissions) {
            if (resources.indexOf(resource) >= 0
                // roles is optional. so remove if role is not defined.
                // if defined, check if the current role is in the list.
                && (!roles || roles.indexOf(role) >= 0)) {
                if (actionPossession) {
                    // e.g. 'create' » 'create:any'
                    // to parse and normalize actionPossession string:
                    var ap = utils_1.utils.normalizeActionPossession({ action: actionPossession }, true);
                    // above will also validate the given actionPossession
                    delete _this._grants[role][resource][ap];
                }
                else {
                    // this is used for AccessControl#removeResources().
                    delete _this._grants[role][resource];
                }
            }
        });
    };
    Object.defineProperty(AccessControl, "Action", {
       
        get: function () {
            return enums_1.Action;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(AccessControl, "Possession", {
        
        get: function () {
            return enums_1.Possession;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(AccessControl, "Error", {
        
        get: function () {
            return core_1.AccessControlError;
        },
        enumerable: true,
        configurable: true
    });
    
    AccessControl.filter = function (data, attributes) {
        return utils_1.utils.filterAll(data, attributes);
    };
    
    AccessControl.isACError = function (object) {
        return object instanceof core_1.AccessControlError;
    };
    
    AccessControl.isAccessControlError = function (object) {
        return AccessControl.isACError(object);
    };
    return AccessControl;
}());
exports.AccessControl = AccessControl;
