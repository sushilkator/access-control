import { AccessControl } from '../';
import { IAccessInfo, AccessControlError } from '../core';
import { Action, Possession, actions, possessions } from '../enums';
import { utils } from '../utils';


class Access {

    
    protected _: IAccessInfo = {};

    
    protected _ac: AccessControl;

    
    protected _grants: any;

    constructor(ac: AccessControl, roleOrInfo?: string | string[] | IAccessInfo, denied: boolean = false) {
        this._ac = ac;
        this._grants = (ac as any)._grants;
        this._.denied = denied;

        if (typeof roleOrInfo === 'string' || Array.isArray(roleOrInfo)) {
            this.role(roleOrInfo);
        } else if (utils.type(roleOrInfo) === 'object') {
            if (Object.keys(roleOrInfo).length === 0) {
                throw new AccessControlError('Invalid IAccessInfo: {}');
            }
            
            roleOrInfo.denied = denied;
            this._ = utils.resetAttributes(roleOrInfo);
            if (utils.isInfoFulfilled(this._)) utils.commitToGrants(this._grants, this._, true);
        } else if (roleOrInfo !== undefined) {
            
            throw new AccessControlError('Invalid role(s), expected a valid string, string[] or IAccessInfo.');
        }
    }

    get denied(): boolean {
        return this._.denied;
    }

    
    role(value: string | string[]): Access {
       
        utils.preCreateRoles(this._grants, value);

        this._.role = value;
        return this;
    }

    
    resource(value: string | string[]): Access {
        utils.hasValidNames(value, true);
        this._.resource = value;
        return this;
    }

    
    attributes(value: string | string[]): Access {
        this._.attributes = value;
        return this;
    }

    
    extend(roles: string | string[]): Access {
        utils.extendRole(this._grants, this._.role, roles);
        return this;
    }

    
    inherit(roles: string | string[]): Access {
        this.extend(roles);
        return this;
    }

    
    grant(roleOrInfo?: string | string[] | IAccessInfo): Access {
        return (new Access(this._ac, roleOrInfo, false)).attributes(['*']);
    }

    
    deny(roleOrInfo?: string | string[] | IAccessInfo): Access {
        return (new Access(this._ac, roleOrInfo, true)).attributes([]);
    }

    
    lock(): Access {
        utils.lockAC(this._ac);
        return this;
    }

    createOwn(resource?: string | string[], attributes?: string | string[]): Access {
        return this._prepareAndCommit(Action.CREATE, Possession.OWN, resource, attributes);
    }

   
    createAny(resource?: string | string[], attributes?: string | string[]): Access {
        return this._prepareAndCommit(Action.CREATE, Possession.ANY, resource, attributes);
    }
    
    create(resource?: string | string[], attributes?: string | string[]): Access {
        return this.createAny(resource, attributes);
    }

    
    readOwn(resource?: string | string[], attributes?: string | string[]): Access {
        return this._prepareAndCommit(Action.READ, Possession.OWN, resource, attributes);
    }

    readAny(resource?: string | string[], attributes?: string | string[]): Access {
        return this._prepareAndCommit(Action.READ, Possession.ANY, resource, attributes);
    }
    
    read(resource?: string | string[], attributes?: string | string[]): Access {
        return this.readAny(resource, attributes);
    }

    updateOwn(resource?: string | string[], attributes?: string | string[]): Access {
        return this._prepareAndCommit(Action.UPDATE, Possession.OWN, resource, attributes);
    }

    updateAny(resource?: string | string[], attributes?: string | string[]): Access {
        return this._prepareAndCommit(Action.UPDATE, Possession.ANY, resource, attributes);
    }
    
    update(resource?: string | string[], attributes?: string | string[]): Access {
        return this.updateAny(resource, attributes);
    }

    deleteOwn(resource?: string | string[], attributes?: string | string[]): Access {
        return this._prepareAndCommit(Action.DELETE, Possession.OWN, resource, attributes);
    }

    deleteAny(resource?: string | string[], attributes?: string | string[]): Access {
        return this._prepareAndCommit(Action.DELETE, Possession.ANY, resource, attributes);
    }
    
    delete(resource?: string | string[], attributes?: string | string[]): Access {
        return this.deleteAny(resource, attributes);
    }

    
    private _prepareAndCommit(action: string, possession: string, resource?: string | string[], attributes?: string | string[]): Access {
        this._.action = action;
        this._.possession = possession;
        if (resource) this._.resource = resource;

        if (this._.denied) {
            this._.attributes = [];
        } else {
            this._.attributes = attributes ? utils.toStringArray(attributes) : ['*'];
        }

        utils.commitToGrants(this._grants, this._, false);

        this._.attributes = undefined;

        return this;
    }

}

export { Access };
