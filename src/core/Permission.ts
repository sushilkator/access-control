// own modules
import { IQueryInfo } from '../core';
import { utils } from '../utils';

class Permission {

    
    private _: any = {};

    
    constructor(grants: any, query: IQueryInfo) {
        this._.attributes = utils.getUnionAttrsOfRoles(grants, query);
        this._.role = query.role;
        this._.resource = query.resource;
    }

    get roles(): string[] {
        return this._.role;
    }

    
    get resource(): string {
        return this._.resource;
    }

   
    get attributes(): string[] {
        return this._.attributes;
    }

   
    get granted(): boolean {
        if (!this.attributes || this.attributes.length === 0) return false;
        return this.attributes.some((attr: string) => {
            return attr.trim().slice(0, 1) !== '!';
        });
    }

   
    filter(data: any): any {
        return utils.filterAll(data, this.attributes);
    }

}

export { Permission };
