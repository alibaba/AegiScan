instance_methods = {
    'NSXPCListener': {
        'initWithMachServiceName:': 'NSXPCConnection',
        'initWithMachServiceName:options:': 'NSXPCConnection',
    }
}

class_methods = {
    'NSXPCListener': {
        'serviceListener': 'NSXPCListener',
    },
    'NSXPCInterface': {
        'interfaceWithProtocol:': 'NSXPCInterface'
    },
    'NSFileManager': {
        'defaultManager': 'NSFileManager'
    }
}

objc_cls_alloc = [
    '_objc_alloc',
    '_objc_alloc_init',
    '_objc_allocWithZone',
    '_objc_opt_new',
]

objc_ret_as_is = [
    # '_objc_autorelease', # autorelease has some differences to retain
    # '_objc_autoreleaseReturnValue'
    '_objc_retain',
    '_objc_retainAutorelease',

    # todo: handle return value
    '_objc_retainAutoreleaseReturnValue',
    '_objc_retainAutoreleasedReturnValue',
    '_objc_unsafeClaimAutoreleasedReturnValue',
]

objc_weak_mov = [
    '_objc_copyWeak',
    '_objc_moveWeak',
    # Treat the following two as mov
    '_objc_initWeak',
    '_objc_storeWeak',
    '_objc_initWeakOrNil',
    '_objc_storeWeakOrNil'
]

objc_weak_ret = [
    '_objc_loadWeakRetained',
    '_objc_loadWeak'
]

objc_strong_mov = [
    '_objc_storeStrong'
]

dispatchers = [
    '_dispatch_sync',
    '_dispatch_async',
]

nullability_annotations = [
    'nonnull',
    'nullable',
    '__nonnull',
    '__nullable',
    '_Nonnull',
    '_Nullable'
]

authentications = [
    'processIdentifier',
    'xpc_connection_get_pid',
    'auditToken',
    'xpc_connection_get_audit_token',
    'effectiveUserIdentifier',
    'effectiveGroupIdentifier',
    'auditSessionIdentifier',
    'kSecGuestAttributeAudit',
    'valueForEntitlement',
    'xpc_connection_copy_entitlement_value',
    'audit_token',
    'entitlement',
    'copyEntitlementsForPid'
]

# Just give some cases, not necessary
str_checks = [
    'matchesInString:options:range:',
    'firstMatchInString:options:range:',
    'rangeOfFirstMatchInString:options:range:',
    'numberOfMatchesInString:options:range:',
    'enumerateMatchesInString:options:range:usingBlock:',
    'containsString:',
    'localizedCaseInsensitiveContainsString:',
    'localizedStandardContainsString:',
    'hasPrefix:',
    'hasSuffix:',
    'isEqualTo:'
    # skip more, e.g., isGreaterThan
]