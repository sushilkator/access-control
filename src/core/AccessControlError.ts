class AccessControlError extends Error {
    public name:string = 'AccessControlError';
    constructor(public message:string = '') {

        super(message)
        Object.setPrototypeOf(this, AccessControlError.prototype);
    }
}

export { AccessControlError };
