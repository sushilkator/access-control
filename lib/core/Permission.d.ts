import { IQueryInfo } from '../core';

declare class Permission {
    private _;
    constructor(grants: any, query: IQueryInfo);
    readonly roles: string[];
    readonly resource: string;
    readonly attributes: string[];
    readonly granted: boolean;
    filter(data: any): any;
}
export { Permission };
