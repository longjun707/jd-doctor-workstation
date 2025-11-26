// A simple shared state module that can be imported by any other module.

/**
 * 从 localStorage 加载租户配置
 */
function loadTenantConfigFromStorage() {
    try {
        const savedConfig = localStorage.getItem('TENANT_CONFIG');
        if (savedConfig) {
            const config = JSON.parse(savedConfig);
            return {
                tenantType: config.tenantType,
                docTenantType: config.docTenantType,
                encryptSuffix: config.encryptSuffix,
                isDisabledTenant: config.isDisabledTenant
            };
        }
    } catch (error) {
        console.error('[State] 加载租户配置失败:', error);
    }
    return null;
}

/**
 * 保存租户配置到 localStorage（永久有效）
 */
export function saveTenantConfig(tenantType, docTenantType, encryptSuffix, isDisabledTenant) {
    try {
        const config = {
            tenantType,
            docTenantType,
            encryptSuffix,
            isDisabledTenant
        };
        localStorage.setItem('TENANT_CONFIG', JSON.stringify(config));
        console.log('[State] 租户配置已保存到 localStorage:', config);
    } catch (error) {
        console.error('[State] 保存租户配置失败:', error);
    }
}

/**
 * 清除保存的租户配置
 */
export function clearTenantConfig() {
    try {
        localStorage.removeItem('TENANT_CONFIG');
        console.log('[State] 已清除保存的租户配置');
    } catch (error) {
        console.error('[State] 清除租户配置失败:', error);
    }
}

// 尝试从 localStorage 加载配置
const savedConfig = loadTenantConfigFromStorage();

export const state = {
    doctorName: null,
    doctorId: null,
    tenantType: savedConfig?.tenantType || null,      // 动态租户类型（优先从缓存加载）
    docTenantType: savedConfig?.docTenantType || null,   // 动态医生租户类型
    encryptSuffix: savedConfig?.encryptSuffix || null,   // 加密后缀（从服务器获取）
    isDisabledTenant: savedConfig?.isDisabledTenant || false, // 是否为禁用租户（JD8888等）
};
