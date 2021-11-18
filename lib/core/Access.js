"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var core_1 = require("../core");
var enums_1 = require("../enums");
var utils_1 = require("../utils");

var Access =  (function () {
   
    function Access(ac, roleOrInfo, denied) {
        if (denied === void 0) { denied = false; }
        
        this._ = {};
        this._ac = ac;
        this._grants = ac._grants;
        this._.denied = denied;
        if (typeof roleOrInfo === 'string' || Array.isArray(roleOrInfo)) {
            this.role(roleOrInfo);
        }
        else if (utils_1.utils.type(roleOrInfo) === 'object') {
            if (Object.keys(roleOrInfo).length === 0) {
                throw new core_1.AccessControlError('Invalid IAccessInfo: {}');
            }
            
            roleOrInfo.denied = denied;
            this._ = utils_1.utils.resetAttributes(roleOrInfo);
            if (utils_1.utils.isInfoFulfilled(this._))
                utils_1.utils.commitToGrants(this._grants, this._, true);
        }
        else if (roleOrInfo !== undefined) {
            
            throw new core_1.AccessControlError('Invalid role(s), expected a valid string, string[] or IAccessInfo.');
        }
    }
    Object.defineProperty(Access.prototype, "denied", {
        // -------------------------------
        //  PUBLIC PROPERTIES
        // -------------------------------
        /**
         *  Specifies whether this access is initally denied.
         *  @name AccessControl~Access#denied
         *  @type {Boolean}
         *  @readonly
         */
        get: function () {
            return this._.denied;
        },
        enumerable: true,
        configurable: true
    });
    
    Access.prototype.role = function (value) {
        // in case chain is not terminated (e.g. `ac.grant('user')`) we'll
        // create/commit the roles to grants with an empty object.
        utils_1.utils.preCreateRoles(this._grants, value);
        this._.role = value;
        return this;
    };
    
    Access.prototype.resource = function (value) {
        // this will throw if any item fails
        utils_1.utils.hasValidNames(value, true);
        this._.resource = value;
        return this;
    };
    
    Access.prototype.attributes = function (value) {
        this._.attributes = value;
        return this;
    };
    
    Access.prototype.extend = function (roles) {
        utils_1.utils.extendRole(this._grants, this._.role, roles);
        return this;
    };
    
    Access.prototype.inherit = function (roles) {
        this.extend(roles);
        return this;
    };
    
    Access.prototype.grant = function (roleOrInfo) {
        return (new Access(this._ac, roleOrInfo, false)).attributes(['*']);
    };
    
    Access.prototype.deny = function (roleOrInfo) {
        return (new Access(this._ac, roleOrInfo, true)).attributes([]);
    };
    
    Access.prototype.lock = function () {
        utils_1.utils.lockAC(this._ac);
        return this;
    };
    
    Access.prototype.createOwn = function (resource, attributes) {
        return this._prepareAndCommit(enums_1.Action.CREATE, enums_1.Possession.OWN, resource, attributes);
    };
    
    Access.prototype.createAny = function (resource, attributes) {
        return this._prepareAndCommit(enums_1.Action.CREATE, enums_1.Possession.ANY, resource, attributes);
    };
    
    Access.prototype.create = function (resource, attributes) {
        return this.createAny(resource, attributes);
    };
    
    Access.prototype.readOwn = function (resource, attributes) {
        return this._prepareAndCommit(enums_1.Action.READ, enums_1.Possession.OWN, resource, attributes);
    };
    
    Access.prototype.readAny = function (resource, attributes) {
        return this._prepareAndCommit(enums_1.Action.READ, enums_1.Possession.ANY, resource, attributes);
    };
    
    Access.prototype.read = function (resource, attributes) {
        return this.readAny(resource, attributes);
    };
    Access.prototype.updateOwn = function (resource, attributes) {
        return this._prepareAndCommit(enums_1.Action.UPDATE, enums_1.Possession.OWN, resource, attributes);
    };
    
    Access.prototype.updateAny = function (resource, attributes) {
        return this._prepareAndCommit(enums_1.Action.UPDATE, enums_1.Possession.ANY, resource, attributes);
    };
    
    Access.prototype.update = function (resource, attributes) {
        return this.updateAny(resource, attributes);
    };
   
    Access.prototype.deleteOwn = function (resource, attributes) {
        return this._prepareAndCommit(enums_1.Action.DELETE, enums_1.Possession.OWN, resource, attributes);
    };
    
    Access.prototype.deleteAny = function (resource, attributes) {
        return this._prepareAndCommit(enums_1.Action.DELETE, enums_1.Possession.ANY, resource, attributes);
    };
    
    Access.prototype.delete = function (resource, attributes) {
        return this.deleteAny(resource, attributes);
    };
    
    Access.prototype._prepareAndCommit = function (action, possession, resource, attributes) {
        this._.action = action;
        this._.possession = possession;
        if (resource)
            this._.resource = resource;
        if (this._.denied) {
            this._.attributes = [];
        }
        else {
            this._.attributes = attributes ? utils_1.utils.toStringArray(attributes) : ['*'];
        }
        utils_1.utils.commitToGrants(this._grants, this._, false);
        this._.attributes = undefined;
        return this;
    };
    return Access;
}());
exports.Access = Access;
