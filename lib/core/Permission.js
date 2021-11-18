"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var utils_1 = require("../utils");
var Permission = /** @class */ (function () {
    
    function Permission(grants, query) {
      
        this._ = {};
        // set attributes first. this also validates the `query` object.
        this._.attributes = utils_1.utils.getUnionAttrsOfRoles(grants, query);
        this._.role = query.role;
        this._.resource = query.resource;
    }
    Object.defineProperty(Permission.prototype, "roles", {
       
        get: function () {
            return this._.role;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Permission.prototype, "resource", {
        
        get: function () {
            return this._.resource;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Permission.prototype, "attributes", {
       
        get: function () {
            return this._.attributes;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Permission.prototype, "granted", {
       
        get: function () {
            if (!this.attributes || this.attributes.length === 0)
                return false;
            // just one non-negated attribute is enough.
            return this.attributes.some(function (attr) {
                return attr.trim().slice(0, 1) !== '!';
            });
        },
        enumerable: true,
        configurable: true
    });
    
    Permission.prototype.filter = function (data) {
        return utils_1.utils.filterAll(data, this.attributes);
    };
    return Permission;
}());
exports.Permission = Permission;
