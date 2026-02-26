import { ref } from "vue";

export type Locale = "en" | "zh-CN";

const STORAGE_KEY = "tavily_proxy_locale";
const FALLBACK_LOCALE: Locale = "en";

const MESSAGES: Record<Locale, Record<string, string>> = {
  en: {
    "app.title": "Tavily Proxy Manager",
    "app.changeKey": "Change Key",
    "app.invalidMasterKey": "Invalid master key",
    "app.menu.dashboard": "Dashboard",
    "app.menu.keys": "Key Management",
    "app.menu.logs": "Logs",
    "app.menu.settings": "Settings",
    "app.menu.logout": "Logout",
    "app.language.english": "English",
    "app.language.chinese": "中文",

    "common.active": "Active",
    "common.disabled": "Disabled",
    "common.enabled": "Enabled",
    "common.cancel": "Cancel",
    "common.dismiss": "Dismiss",
    "common.copiedToClipboard": "Copied to clipboard",
    "common.copyFailed": "Copy failed",
    "common.saveFailed": "Save failed",
    "common.resetFailed": "Reset failed",
    "common.deleteFailed": "Delete failed",
    "common.updateFailed": "Update failed",
    "common.createFailed": "Create failed",
    "common.syncFailed": "Sync failed",
    "common.noData": "No Data",
    "common.viewDetails": "View Details",
    "common.andMore": "…and {count} more",

    "auth.title": "Authentication Required",
    "auth.welcome": "Welcome Back",
    "auth.subtitle": "Please enter your master key to manage the proxy.",
    "auth.masterKeyLabel": "Master Key",
    "auth.masterKeyPlaceholder": "Enter your master key",
    "auth.accessDashboard": "Access Dashboard",
    "auth.footer":
      "The master key is required to authenticate administrative requests.",

    "dashboard.title": "Dashboard",
    "dashboard.refreshData": "Refresh Data",
    "dashboard.stats.remainingQuota": "Remaining Quota",
    "dashboard.stats.totalUsed": "Total Used",
    "dashboard.stats.activeKeys": "Active Keys",
    "dashboard.stats.todayRequests": "Today Requests",
    "dashboard.resourceUsage.title": "Resource Usage",
    "dashboard.resourceUsage.usedPct": "{pct}% Used",
    "dashboard.resourceUsage.monthlyQuotaConsumption":
      "Monthly Quota Consumption",
    "dashboard.requestAnalytics.title": "Request Analytics",
    "dashboard.requestAnalytics.hour": "Hour",
    "dashboard.requestAnalytics.day": "Day",
    "dashboard.requestAnalytics.month": "Month",
    "dashboard.timeseries.allRequests": "All Requests",
    "dashboard.timeseries.search": "Search",
    "dashboard.errors.loadStats": "Failed to load stats",
    "dashboard.errors.loadChart": "Failed to load chart",

    "keys.title": "Key Management",
    "keys.subtitle": "Manage your Tavily API keys and their quotas.",
    "keys.tooltip.maxConcurrent":
      "Max concurrent /usage requests during Sync All.",
    "keys.tooltip.delayBetweenUsage":
      "Delay between /usage requests during Sync All.",
    "keys.syncAll": "Sync All",
    "keys.exportAll": "Export Keys",
    "keys.batchAdd": "Batch Add",
    "keys.addNewKey": "Add New Key",
    "keys.suffix.conc": "conc",
    "keys.suffix.seconds": "s",
    "keys.addModal.title": "Add API Key",
    "keys.addModal.apiKey": "Tavily API Key",
    "keys.addModal.alias": "Alias",
    "keys.addModal.aliasPlaceholder": "Account Name (e.g. Personal)",
    "keys.addModal.totalQuota": "Total Quota",
    "keys.addModal.createKey": "Create Key",
    "keys.batchModal.title": "Batch Add API Keys",
    "keys.batchModal.help": "Paste one Tavily API key per line.",
    "keys.batchModal.failedHeader": "Failed to add {count} key(s).",
    "keys.batchModal.addKeys": "Add Keys",
    "keys.editModal.title": "Edit Key",
    "keys.editModal.alias": "Alias",
    "keys.editModal.totalQuota": "Total Quota",
    "keys.editModal.usedQuota": "Used Quota",
    "keys.editModal.status": "Status",
    "keys.editModal.saveChanges": "Save Changes",
    "keys.errors.loadKeys": "Failed to load keys",
    "keys.errors.needAtLeastOneKey": "Please enter at least one key",
    "keys.errors.syncAllFailed": "Sync all failed",
    "keys.errors.exportFailed": "Export failed",
    "keys.messages.syncAllStarted": "Sync started in background",
    "keys.messages.syncAllProgress":
      "Syncing: {completed}/{total} (failed: {failed})",
    "keys.messages.syncAllSuccess":
      "Synced: {succeeded}/{total} (failed: {failed})",
    "keys.messages.exported": "Exported {count} key(s)",
    "keys.messages.keyAdded": "Key added",
    "keys.messages.addedKeys": "Added {count} keys",
    "keys.messages.addedPartial":
      "Added {succeeded}/{total} keys (failed: {failed})",
    "keys.messages.updated": "Updated",
    "keys.messages.quotaReset": "Quota reset",
    "keys.messages.syncedFromUsage": "Synced from /usage",
    "keys.messages.deleted": "Deleted",
    "keys.table.alias": "Alias",
    "keys.table.key": "Key",
    "keys.table.usageQuota": "Usage & Quota",
    "keys.table.status": "Status",
    "keys.table.actions": "Actions",
    "keys.actions.syncUsage": "Sync Usage",
    "keys.actions.resetQuota": "Reset Quota",
    "keys.actions.editKey": "Edit Key",
    "keys.actions.deleteKey": "Delete Key",
    "keys.actions.deleteInvalid": "Delete Invalid",
    "keys.confirm.deleteKey": "Are you sure you want to delete this key?",
    "keys.confirm.deleteInvalid":
      "Delete {count} invalid key(s)? This cannot be undone.",
    "keys.status.invalid": "Invalid",
    "keys.errors.deleteInvalidFailed": "Failed to delete invalid keys",
    "keys.messages.deletedInvalid": "Deleted {count} invalid key(s)",

    "logs.title": "Request Logs",
    "logs.subtitle":
      "Historical list of all API requests proxied through the system.",
    "logs.refreshLogs": "Refresh Logs",
    "logs.clearLogs": "Clear Logs",
    "logs.filter.statusCodePlaceholder": "Status code (e.g. 200)",
    "logs.filter.allStatusCodes": "All status codes",
    "logs.confirm.clearLogs":
      "This will permanently delete all request logs. Proceed?",
    "logs.detail.title": "Log Detail View",
    "logs.detail.endpoint": "Endpoint",
    "logs.detail.status": "Status",
    "logs.detail.clientIp": "Client IP",
    "logs.detail.latency": "Latency",
    "logs.detail.keyUsed": "Key Used",
    "logs.detail.requestBody": "Request Body",
    "logs.detail.responseBody": "Response Body",
    "logs.errors.loadLogs": "Failed to load logs",
    "logs.errors.loadStatusCodes": "Failed to load status codes",
    "logs.errors.clearLogs": "Failed to clear logs",
    "logs.messages.clearedLogs": "Cleared {count} logs",
    "logs.table.time": "Time",
    "logs.table.clientIp": "Client IP",
    "logs.table.keyAlias": "Key Alias",
    "logs.table.endpoint": "Endpoint",
    "logs.table.latency": "Latency",
    "logs.table.status": "Status",
    "logs.table.actions": "Actions",

    "settings.title": "Settings",
    "settings.subtitle": "Configure system-wide settings and master key.",
    "settings.masterAuth.title": "Master Authentication",
    "settings.masterAuth.alert":
      "The master key is used to authenticate all administrative requests. Keep it secure.",
    "settings.masterAuth.currentKey": "Current Master Key",
    "settings.masterAuth.noKey": "No master key set",
    "settings.masterAuth.reset": "Reset Master Key",
    "settings.masterAuth.resetConfirm":
      "This will invalidate the current key. Existing clients must be updated. Proceed?",
    "settings.autoSync.title": "Quota Auto-Sync",
    "settings.autoSync.label": "Automatic Synchronization",
    "settings.autoSync.interval": "Sync Interval (minutes)",
    "settings.autoSync.concurrency": "Sync Concurrency",
    "settings.autoSync.perKeyDelay": "Per-Key Delay (seconds)",
    "settings.autoSync.lastAttempt": "Last Attempt",
    "settings.autoSync.lastSuccess": "Last Success",
    "settings.autoSync.save": "Save Sync Configuration",
    "settings.logCleanup.title": "Log Cleanup",
    "settings.logCleanup.alertPrefix": "Cleans only ",
    "settings.logCleanup.requestLogs": "Request Logs",
    "settings.logCleanup.alertSuffix":
      ". Dashboard statistics remain available even after log cleanup.",
    "settings.logCleanup.enableLogging": "Enable Request Logging",
    "settings.logCleanup.retention": "Retention (days, 0 = disable)",
    "settings.logCleanup.lastCleanup": "Last Cleanup",
    "settings.logCleanup.save": "Save Log Cleanup Configuration",
    "settings.errors.loadMasterKey": "Failed to load master key",
    "settings.errors.loadAutoSync": "Failed to load auto sync settings",
    "settings.errors.loadLogCleanup": "Failed to load log cleanup settings",
    "settings.messages.updated": "Settings updated successfully",
    "settings.messages.masterKeyReset": "Master key reset successfully",
    "settings.cache.title": "Search Cache",
    "settings.cache.label": "Enable Cache",
    "settings.cache.ttl": "Cache TTL (seconds)",
    "settings.cache.entries": "Cached Entries",
    "settings.cache.hits": "Total Hits",
    "settings.cache.size": "Approximate Size",
    "settings.cache.clear": "Clear Cache",
    "settings.cache.clearConfirm": "This will delete all cached search results. Proceed?",
    "settings.cache.save": "Save Cache Configuration",
    "settings.errors.loadCache": "Failed to load cache settings",
    "dashboard.stats.cacheHits": "Cache Hits",
    "logs.table.cacheHit": "Cache",

    "units.minutes": "min",
    "units.days": "days",
    "units.seconds": "s",
  },
  "zh-CN": {
    "app.title": "Tavily 代理管理",
    "app.invalidMasterKey": "主密钥无效",
    "app.menu.dashboard": "仪表盘",
    "app.menu.keys": "密钥管理",
    "app.menu.logs": "日志",
    "app.menu.settings": "设置",
    "app.menu.logout": "退出",
    "app.language.english": "English",
    "app.language.chinese": "中文",

    "common.active": "启用",
    "common.disabled": "禁用",
    "common.enabled": "启用",
    "common.cancel": "取消",
    "common.dismiss": "关闭",
    "common.copiedToClipboard": "已复制到剪贴板",
    "common.copyFailed": "复制失败",
    "common.saveFailed": "保存失败",
    "common.resetFailed": "重置失败",
    "common.deleteFailed": "删除失败",
    "common.updateFailed": "更新失败",
    "common.createFailed": "创建失败",
    "common.syncFailed": "同步失败",
    "common.noData": "无数据",
    "common.viewDetails": "查看详情",
    "common.andMore": "…还有 {count} 个",

    "auth.title": "需要身份验证",
    "auth.welcome": "欢迎回来",
    "auth.subtitle": "请输入主密钥以管理代理。",
    "auth.masterKeyLabel": "主密钥",
    "auth.masterKeyPlaceholder": "请输入主密钥",
    "auth.accessDashboard": "进入控制台",
    "auth.footer": "主密钥用于验证所有管理请求。",

    "dashboard.title": "仪表盘",
    "dashboard.refreshData": "刷新数据",
    "dashboard.stats.remainingQuota": "剩余额度",
    "dashboard.stats.totalUsed": "已用额度",
    "dashboard.stats.activeKeys": "可用密钥",
    "dashboard.stats.todayRequests": "今日请求",
    "dashboard.resourceUsage.title": "资源使用",
    "dashboard.resourceUsage.usedPct": "已使用 {pct}%",
    "dashboard.resourceUsage.monthlyQuotaConsumption": "月度额度消耗",
    "dashboard.requestAnalytics.title": "请求分析",
    "dashboard.requestAnalytics.hour": "小时",
    "dashboard.requestAnalytics.day": "天",
    "dashboard.requestAnalytics.month": "月",
    "dashboard.timeseries.allRequests": "全部请求",
    "dashboard.timeseries.search": "搜索",
    "dashboard.errors.loadStats": "统计信息加载失败",
    "dashboard.errors.loadChart": "图表加载失败",

    "keys.title": "密钥管理",
    "keys.subtitle": "管理 Tavily API 密钥及其额度。",
    "keys.tooltip.maxConcurrent": "“同步全部”时 /usage 请求的最大并发数。",
    "keys.tooltip.delayBetweenUsage": "“同步全部”时 /usage 请求之间的延迟。",
    "keys.syncAll": "同步全部",
    "keys.exportAll": "导出密钥",
    "keys.batchAdd": "批量添加",
    "keys.addNewKey": "添加新密钥",
    "keys.suffix.conc": "并发",
    "keys.suffix.seconds": "秒",
    "keys.addModal.title": "添加 API 密钥",
    "keys.addModal.apiKey": "Tavily API 密钥",
    "keys.addModal.alias": "别名",
    "keys.addModal.aliasPlaceholder": "账户名称（例如：个人）",
    "keys.addModal.totalQuota": "总额度",
    "keys.addModal.createKey": "创建密钥",
    "keys.batchModal.title": "批量添加 API 密钥",
    "keys.batchModal.help": "每行粘贴一个 Tavily API 密钥。",
    "keys.batchModal.failedHeader": "添加失败 {count} 个密钥。",
    "keys.batchModal.addKeys": "添加",
    "keys.editModal.title": "编辑密钥",
    "keys.editModal.alias": "别名",
    "keys.editModal.totalQuota": "总额度",
    "keys.editModal.usedQuota": "已用额度",
    "keys.editModal.status": "状态",
    "keys.editModal.saveChanges": "保存更改",
    "keys.errors.loadKeys": "密钥加载失败",
    "keys.errors.needAtLeastOneKey": "请至少输入一个密钥",
    "keys.errors.syncAllFailed": "同步全部失败",
    "keys.errors.exportFailed": "导出失败",
    "keys.messages.syncAllStarted": "已在后台开始同步",
    "keys.messages.syncAllProgress":
      "同步中：{completed}/{total}（失败：{failed}）",
    "keys.messages.syncAllSuccess":
      "同步完成：{succeeded}/{total}（失败：{failed}）",
    "keys.messages.exported": "已导出 {count} 个密钥",
    "keys.messages.keyAdded": "已添加密钥",
    "keys.messages.addedKeys": "已添加 {count} 个密钥",
    "keys.messages.addedPartial":
      "已添加 {succeeded}/{total} 个密钥（失败：{failed}）",
    "keys.messages.updated": "已更新",
    "keys.messages.quotaReset": "额度已重置",
    "keys.messages.syncedFromUsage": "已从 /usage 同步",
    "keys.messages.deleted": "已删除",
    "keys.table.alias": "别名",
    "keys.table.key": "密钥",
    "keys.table.usageQuota": "用量与额度",
    "keys.table.status": "状态",
    "keys.table.actions": "操作",
    "keys.actions.syncUsage": "同步用量",
    "keys.actions.resetQuota": "重置额度",
    "keys.actions.editKey": "编辑",
    "keys.actions.deleteKey": "删除",
    "keys.actions.deleteInvalid": "删除无效密钥",
    "keys.confirm.deleteKey": "确定要删除该密钥吗？",
    "keys.confirm.deleteInvalid":
      "将删除 {count} 个无效密钥，且不可恢复，确定继续吗？",
    "keys.status.invalid": "无效",
    "keys.errors.deleteInvalidFailed": "删除无效密钥失败",
    "keys.messages.deletedInvalid": "已删除 {count} 个无效密钥",

    "logs.title": "请求日志",
    "logs.subtitle": "系统代理的所有 API 请求历史记录。",
    "logs.refreshLogs": "刷新日志",
    "logs.clearLogs": "清空日志",
    "logs.filter.statusCodePlaceholder": "状态码（例如 200）",
    "logs.filter.allStatusCodes": "全部状态码",
    "logs.confirm.clearLogs": "这将永久删除所有请求日志，确定继续吗？",
    "logs.detail.title": "日志详情",
    "logs.detail.endpoint": "接口",
    "logs.detail.status": "状态",
    "logs.detail.clientIp": "客户端 IP",
    "logs.detail.latency": "耗时",
    "logs.detail.keyUsed": "使用的密钥",
    "logs.detail.requestBody": "请求体",
    "logs.detail.responseBody": "响应体",
    "logs.errors.loadLogs": "日志加载失败",
    "logs.errors.loadStatusCodes": "状态码统计加载失败",
    "logs.errors.clearLogs": "清空日志失败",
    "logs.messages.clearedLogs": "已清空 {count} 条日志",
    "logs.table.time": "时间",
    "logs.table.clientIp": "客户端 IP",
    "logs.table.keyAlias": "密钥别名",
    "logs.table.endpoint": "接口",
    "logs.table.latency": "耗时",
    "logs.table.status": "状态",
    "logs.table.actions": "操作",

    "settings.title": "设置",
    "settings.subtitle": "配置系统设置与主密钥。",
    "settings.masterAuth.title": "主密钥认证",
    "settings.masterAuth.alert": "主密钥用于验证所有管理请求，请妥善保管。",
    "settings.masterAuth.currentKey": "当前主密钥",
    "settings.masterAuth.noKey": "尚未设置主密钥",
    "settings.masterAuth.reset": "重置主密钥",
    "settings.masterAuth.resetConfirm":
      "此操作将使当前密钥失效，现有客户端需要更新。确定继续吗？",
    "settings.autoSync.title": "额度自动同步",
    "settings.autoSync.label": "自动同步",
    "settings.autoSync.interval": "同步间隔（分钟）",
    "settings.autoSync.concurrency": "同步并发",
    "settings.autoSync.perKeyDelay": "每个密钥延迟（秒）",
    "settings.autoSync.lastAttempt": "最近尝试",
    "settings.autoSync.lastSuccess": "最近成功",
    "settings.autoSync.save": "保存同步配置",
    "settings.logCleanup.title": "日志清理",
    "settings.logCleanup.alertPrefix": "仅清理",
    "settings.logCleanup.requestLogs": "请求日志",
    "settings.logCleanup.alertSuffix": "。清理后仪表盘统计仍会保留。",
    "settings.logCleanup.enableLogging": "开启日志",
    "settings.logCleanup.retention": "保留天数（0 表示禁用）",
    "settings.logCleanup.lastCleanup": "最近清理",
    "settings.logCleanup.save": "保存日志清理配置",
    "settings.errors.loadMasterKey": "主密钥加载失败",
    "settings.errors.loadAutoSync": "自动同步设置加载失败",
    "settings.errors.loadLogCleanup": "日志清理设置加载失败",
    "settings.messages.updated": "设置已更新",
    "settings.messages.masterKeyReset": "主密钥重置成功",
    "settings.cache.title": "搜索缓存",
    "settings.cache.label": "启用缓存",
    "settings.cache.ttl": "缓存 TTL（秒）",
    "settings.cache.entries": "缓存条目",
    "settings.cache.hits": "总命中次数",
    "settings.cache.size": "大约大小",
    "settings.cache.clear": "清除缓存",
    "settings.cache.clearConfirm": "这将删除所有缓存的搜索结果，确定继续吗？",
    "settings.cache.save": "保存缓存配置",
    "settings.errors.loadCache": "缓存设置加载失败",
    "dashboard.stats.cacheHits": "缓存命中",
    "logs.table.cacheHit": "缓存",

    "units.minutes": "分钟",
    "units.days": "天",
    "units.seconds": "秒",
  },
};

function normalizeLocale(value: unknown): Locale {
  if (value === "zh-CN") return "zh-CN";
  return "en";
}

function detectBrowserLocale(): Locale {
  const nav =
    typeof navigator !== "undefined" && typeof navigator.language === "string"
      ? navigator.language
      : "";
  if (nav.toLowerCase().startsWith("zh")) return "zh-CN";
  return "en";
}

function getInitialLocale(): Locale {
  const stored = readStorage(STORAGE_KEY);
  if (stored) return normalizeLocale(stored);
  return detectBrowserLocale();
}

export const locale = ref<Locale>(getInitialLocale());

export function setLocale(next: Locale): void {
  locale.value = next;
  writeStorage(STORAGE_KEY, next);
  applyLocaleToDocument();
}

export function applyLocaleToDocument(): void {
  if (typeof document === "undefined") return;
  document.documentElement.lang = locale.value;
  const title =
    MESSAGES[locale.value]["app.title"] ??
    MESSAGES[FALLBACK_LOCALE]["app.title"];
  if (title) document.title = title;
}

function interpolate(
  template: string,
  params?: Record<string, unknown>,
): string {
  if (!params) return template;
  return template.replace(/\{(\w+)\}/g, (match, key) => {
    const value = params[key];
    if (value === undefined || value === null) return match;
    return String(value);
  });
}

export function t(key: string, params?: Record<string, unknown>): string {
  const template =
    MESSAGES[locale.value][key] ?? MESSAGES[FALLBACK_LOCALE][key] ?? key;
  return interpolate(template, params);
}

function readStorage(key: string): string | null {
  if (typeof localStorage === "undefined") return null;
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeStorage(key: string, value: string): void {
  if (typeof localStorage === "undefined") return;
  try {
    localStorage.setItem(key, value);
  } catch {
    // Ignore storage write errors (e.g. disabled storage).
  }
}
