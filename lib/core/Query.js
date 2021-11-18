"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var core_1 = require("../core");
var enums_1 = require("../enums");
var utils_1 = require("../utils");

var Query =  (function () {
    
    function Query(grants, roleOrInfo) {
        
        this._ = {};
        this._grants = grants;
        if (typeof roleOrInfo === 'string' || Array.isArray(roleOrInfo)) {
          
            this.role(roleOrInfo);
        }
        else if (utils_1.utils.type(roleOrInfo) === 'object') {
            
            if (Object.keys(roleOrInfo).length === 0) {
                throw new core_1.AccessControlError('Invalid IQueryInfo: {}');
            }
            this._ = roleOrInfo;
        }
        else if (roleOrInfo !== undefined) {
           
            throw new core_1.AccessControlError('Invalid role(s), expected a valid string, string[] or IQueryInfo.');
        }
    }
   
    Query.prototype.role = function (role) {
        this._.role = role;
        return this;
    };
     
    Query.prototype.resource = function (resource) {
        this._.resource = resource;
        return this;
    };
   
    Query.prototype.createOwn = function (resource) {
        return this._getPermission(enums_1.Action.CREATE, enums_1.Possession.OWN, resource);
    };
   
    Query.prototype.createAny = function (resource) {
        return this._getPermission(enums_1.Action.CREATE, enums_1.Possession.ANY, resource);
    };
   
    Query.prototype.create = function (resource) {
        return this.createAny(resource);
    };
    
    Query.prototype.readOwn = function (resource) {
        return this._getPermission(enums_1.Action.READ, enums_1.Possession.OWN, resource);
    };
   
    Query.prototype.readAny = function (resource) {
        return this._getPermission(enums_1.Action.READ, enums_1.Possession.ANY, resource);
    };
    
    Query.prototype.read = function (resource) {
        return this.readAny(resource);
    };
   
    Query.prototype.updateOwn = function (resource) {
        return this._getPermission(enums_1.Action.UPDATE, enums_1.Possession.OWN, resource);
    };
   
    Query.prototype.updateAny = function (resource) {
        return this._getPermission(enums_1.Action.UPDATE, enums_1.Possession.ANY, resource);
    };
   
    Query.prototype.update = function (resource) {
        return this.updateAny(resource);
    };
    
    Query.prototype.deleteOwn = function (resource) {
        return this._getPermission(enums_1.Action.DELETE, enums_1.Possession.OWN, resource);
    };
    
    Query.prototype.deleteAny = function (resource) {
        return this._getPermission(enums_1.Action.DELETE, enums_1.Possession.ANY, resource);
    };
   
    Query.prototype.delete = function (resource) {
        return this.deleteAny(resource);
    };
    
    Query.prototype._getPermission = function (action, possession, resource) {
        this._.action = action;
        this._.possession = possession;
        if (resource)
            this._.resource = resource;
        return new core_1.Permission(this._grants, this._);
    };
    return Query;
}());
exports.Query = Query;
