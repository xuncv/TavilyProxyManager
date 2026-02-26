<template>
  <n-space vertical size="large">
    <div class="page-header">
      <div class="header-info">
        <h2 class="page-title">{{ t("settings.title") }}</h2>
        <div class="page-subtitle">
          {{ t("settings.subtitle") }}
        </div>
      </div>
    </div>

    <n-grid cols="1 m:2" :x-gap="16" :y-gap="16" responsive="screen">
      <n-gi>
        <n-card :title="t('settings.masterAuth.title')" class="settings-card">
          <template #header-extra>
            <n-icon :component="LockClosedOutline" size="20" />
          </template>
          <n-space vertical size="large">
            <n-alert type="warning" :show-icon="true" size="small">
              {{ t("settings.masterAuth.alert") }}
            </n-alert>
            <div>
              <div class="field-label">{{ t("settings.masterAuth.currentKey") }}</div>
              <n-input-group>
                <n-input
                  :value="masterKey"
                  readonly
                  type="password"
                  show-password-on="mousedown"
                  :placeholder="t('settings.masterAuth.noKey')"
                />
                <n-button
                  type="primary"
                  ghost
                  @click="copy"
                  :disabled="!masterKey"
                >
                  <template #icon><n-icon :component="CopyOutline" /></template>
                </n-button>
              </n-input-group>
            </div>
            <n-popconfirm @positive-click="resetKey">
              <template #trigger>
                <n-button block type="error" secondary>
                  <template #icon
                    ><n-icon :component="RefreshOutline"
                  /></template>
                  {{ t("settings.masterAuth.reset") }}
                </n-button>
              </template>
              {{ t("settings.masterAuth.resetConfirm") }}
            </n-popconfirm>
          </n-space>
        </n-card>
      </n-gi>

      <n-gi>
        <n-card :title="t('settings.autoSync.title')" class="settings-card">
          <template #header-extra>
            <n-icon :component="SyncOutline" size="20" />
          </template>
          <n-space vertical size="large">
            <n-form :model="autoSync" label-placement="top" size="medium">
              <n-form-item :label="t('settings.autoSync.label')">
                <n-space align="center">
                  <n-switch v-model:value="autoSync.enabled" />
                  <span>{{
                    autoSync.enabled ? t("common.enabled") : t("common.disabled")
                  }}</span>
                </n-space>
              </n-form-item>
              <n-form-item :label="t('settings.autoSync.interval')">
                <n-input-number
                  v-model:value="autoSync.interval_minutes"
                  :min="1"
                  :max="1440"
                  style="width: 100%"
                >
                  <template #suffix>{{ t("units.minutes") }}</template>
                </n-input-number>
              </n-form-item>
              <n-form-item :label="t('settings.autoSync.perKeyDelay')">
                <n-input-number
                  v-model:value="autoSync.request_interval_seconds"
                  :min="0"
                  :max="60"
                  style="width: 100%"
                >
                  <template #suffix>{{ t("units.seconds") }}</template>
                </n-input-number>
              </n-form-item>
            </n-form>

            <div class="sync-stats">
              <div class="sync-stat-item">
                <span class="label">{{ t("settings.autoSync.lastAttempt") }}</span>
                <span class="value">{{
                  autoSync.last_run_at ? formatDate(autoSync.last_run_at) : "-"
                }}</span>
              </div>
              <div class="sync-stat-item">
                <span class="label">{{ t("settings.autoSync.lastSuccess") }}</span>
                <span class="value success">{{
                  autoSync.last_success_at
                    ? formatDate(autoSync.last_success_at)
                    : "-"
                }}</span>
              </div>
            </div>

            <n-alert
              v-if="autoSync.last_error"
              type="error"
              size="small"
              :bordered="false"
              class="error-alert"
            >
              {{ autoSync.last_error }}
            </n-alert>

            <n-button
              type="primary"
              block
              :loading="savingAutoSync"
              @click="saveAutoSync"
            >
              {{ t("settings.autoSync.save") }}
            </n-button>
          </n-space>
        </n-card>
      </n-gi>

      <n-gi>
        <n-card :title="t('settings.logCleanup.title')" class="settings-card">
          <template #header-extra>
            <n-icon :component="TrashOutline" size="20" />
          </template>
          <n-space vertical size="large">
            <n-alert type="info" :show-icon="true" size="small">
              {{ t("settings.logCleanup.alertPrefix") }}<strong>{{
                t("settings.logCleanup.requestLogs")
              }}</strong>{{ t("settings.logCleanup.alertSuffix") }}
            </n-alert>

            <n-form :model="logCleanup" label-placement="top" size="medium">
              <n-form-item :label="t('settings.logCleanup.enableLogging')">
                <n-space align="center">
                  <n-switch v-model:value="logCleanup.logging_enabled" />
                  <span>{{
                    logCleanup.logging_enabled
                      ? t("common.enabled")
                      : t("common.disabled")
                  }}</span>
                </n-space>
              </n-form-item>
              <n-form-item :label="t('settings.logCleanup.retention')">
                <n-input-number
                  v-model:value="logCleanup.retention_days"
                  :min="0"
                  :max="3650"
                  style="width: 100%"
                >
                  <template #suffix>{{ t("units.days") }}</template>
                </n-input-number>
              </n-form-item>
            </n-form>

            <div class="sync-stats">
              <div class="sync-stat-item">
                <span class="label">{{ t("settings.logCleanup.lastCleanup") }}</span>
                <span class="value">{{
                  logCleanup.last_run_at ? formatDate(logCleanup.last_run_at) : "-"
                }}</span>
              </div>
            </div>

            <n-alert
              v-if="logCleanup.last_error"
              type="error"
              size="small"
              :bordered="false"
              class="error-alert"
            >
              {{ logCleanup.last_error }}
            </n-alert>

            <n-button
              type="primary"
              block
              :loading="savingLogCleanup"
              @click="saveLogCleanup"
            >
              {{ t("settings.logCleanup.save") }}
            </n-button>
          </n-space>
        </n-card>
      </n-gi>

      <n-gi>
        <n-card :title="t('settings.cache.title')" class="settings-card">
          <template #header-extra>
            <n-icon :component="ServerOutline" size="20" />
          </template>
          <n-space vertical size="large">
            <n-form :model="cacheSettings" label-placement="top" size="medium">
              <n-form-item :label="t('settings.cache.label')">
                <n-space align="center">
                  <n-switch v-model:value="cacheSettings.enabled" />
                  <span>{{
                    cacheSettings.enabled ? t("common.enabled") : t("common.disabled")
                  }}</span>
                </n-space>
              </n-form-item>
              <n-form-item :label="t('settings.cache.ttl')">
                <n-input-number
                  v-model:value="cacheSettings.ttl_seconds"
                  :min="60"
                  :max="604800"
                  style="width: 100%"
                >
                  <template #suffix>{{ t("units.seconds") }}</template>
                </n-input-number>
              </n-form-item>
            </n-form>

            <div class="sync-stats">
              <div class="sync-stat-item">
                <span class="label">{{ t("settings.cache.entries") }}</span>
                <span class="value">{{ cacheStatsData.entry_count }}</span>
              </div>
              <div class="sync-stat-item">
                <span class="label">{{ t("settings.cache.hits") }}</span>
                <span class="value">{{ cacheStatsData.total_hits }}</span>
              </div>
              <div class="sync-stat-item">
                <span class="label">{{ t("settings.cache.size") }}</span>
                <span class="value">{{ formatBytes(cacheStatsData.total_size_bytes) }}</span>
              </div>
            </div>

            <n-popconfirm @positive-click="clearCache">
              <template #trigger>
                <n-button block type="error" secondary>
                  <template #icon><n-icon :component="TrashOutline" /></template>
                  {{ t("settings.cache.clear") }}
                </n-button>
              </template>
              {{ t("settings.cache.clearConfirm") }}
            </n-popconfirm>

            <n-button
              type="primary"
              block
              :loading="savingCache"
              @click="saveCache"
            >
              {{ t("settings.cache.save") }}
            </n-button>
          </n-space>
        </n-card>
      </n-gi>
    </n-grid>
  </n-space>
</template>

<script setup lang="ts">
import { onMounted, ref } from "vue";
import {
  NAlert,
  NButton,
  NCard,
  NForm,
  NFormItem,
  NGi,
  NGrid,
  NIcon,
  NInput,
  NInputGroup,
  NInputNumber,
  NPopconfirm,
  NSpace,
  NSwitch,
  useMessage,
} from "naive-ui";
import {
  CopyOutline,
  LockClosedOutline,
  RefreshOutline,
  ServerOutline,
  SyncOutline,
  TrashOutline,
} from "@vicons/ionicons5";
import { api, setMasterKey as storeMasterKey } from "../api/client";
import { writeClipboardText } from "../utils/clipboard";
import { locale, t } from "../i18n";

const message = useMessage();
const masterKey = ref("");
const savingAutoSync = ref(false);
const savingLogCleanup = ref(false);
const savingCache = ref(false);

const cacheSettings = ref<{
  enabled: boolean;
  ttl_seconds: number;
}>({
  enabled: false,
  ttl_seconds: 43200,
});

const cacheStatsData = ref<{
  entry_count: number;
  total_hits: number;
  total_size_bytes: number;
}>({
  entry_count: 0,
  total_hits: 0,
  total_size_bytes: 0,
});

const autoSync = ref<{
  enabled: boolean;
  interval_minutes: number;
  request_interval_seconds: number;
  last_run_at: string | null;
  last_success_at: string | null;
  last_error: string;
}>({
  enabled: false,
  interval_minutes: 60,
  request_interval_seconds: 0,
  last_run_at: null,
  last_success_at: null,
  last_error: "",
});

const logCleanup = ref<{
  logging_enabled: boolean;
  retention_days: number;
  last_run_at: string | null;
  last_error: string;
}>({
  logging_enabled: true,
  retention_days: 30,
  last_run_at: null,
  last_error: "",
});

function formatDate(dateStr: string) {
  const date = new Date(dateStr);
  return date.toLocaleString(locale.value);
}

function normalizeAutoSyncIntervalMinutes(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return 60;
  return Math.min(1440, Math.max(1, Math.floor(parsed)));
}

function normalizeAutoSyncRequestIntervalSeconds(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return 0;
  return Math.min(60, Math.max(0, Math.floor(parsed)));
}

async function load() {
  try {
    const { data } = await api.get<{ master_key: string }>(
      "/api/settings/master-key"
    );
    masterKey.value = data.master_key;
  } catch (err: any) {
    message.error(err?.response?.data?.error ?? t("settings.errors.loadMasterKey"));
  }
}

async function loadAutoSync() {
  try {
    const { data } = await api.get<{
      enabled: boolean;
      interval_minutes: number;
      request_interval_seconds: number;
      last_run_at: string | null;
      last_success_at: string | null;
      last_error: string;
    }>("/api/settings/auto-sync");
    autoSync.value = {
      enabled: data.enabled,
      interval_minutes: normalizeAutoSyncIntervalMinutes(data.interval_minutes),
      request_interval_seconds: normalizeAutoSyncRequestIntervalSeconds(
        data.request_interval_seconds
      ),
      last_run_at: data.last_run_at,
      last_success_at: data.last_success_at,
      last_error: data.last_error ?? "",
    };
  } catch (err: any) {
    message.error(
      err?.response?.data?.error ?? t("settings.errors.loadAutoSync")
    );
  }
}

async function saveAutoSync() {
  savingAutoSync.value = true;
  try {
    const payload = {
      enabled: autoSync.value.enabled,
      interval_minutes: normalizeAutoSyncIntervalMinutes(
        autoSync.value.interval_minutes
      ),
      request_interval_seconds: normalizeAutoSyncRequestIntervalSeconds(
        autoSync.value.request_interval_seconds
      ),
    };
    await api.put("/api/settings/auto-sync", {
      ...payload,
    });
    await loadAutoSync();
    message.success(t("settings.messages.updated"));
  } catch (err: any) {
    message.error(err?.response?.data?.error ?? t("common.saveFailed"));
  } finally {
    savingAutoSync.value = false;
  }
}

async function loadLogCleanup() {
  try {
    const { data } = await api.get<{
      logging_enabled: boolean;
      retention_days: number;
      last_run_at: string | null;
      last_error: string;
    }>("/api/settings/log-cleanup");
    logCleanup.value = {
      logging_enabled: data.logging_enabled ?? true,
      retention_days: data.retention_days,
      last_run_at: data.last_run_at,
      last_error: data.last_error ?? "",
    };
  } catch (err: any) {
    message.error(
      err?.response?.data?.error ?? t("settings.errors.loadLogCleanup")
    );
  }
}

async function saveLogCleanup() {
  savingLogCleanup.value = true;
  try {
    await api.put("/api/settings/log-cleanup", {
      logging_enabled: logCleanup.value.logging_enabled,
      retention_days: logCleanup.value.retention_days,
    });
    await loadLogCleanup();
    message.success(t("settings.messages.updated"));
  } catch (err: any) {
    message.error(err?.response?.data?.error ?? t("common.saveFailed"));
  } finally {
    savingLogCleanup.value = false;
  }
}

async function loadCache() {
  try {
    const [settingsRes, statsRes] = await Promise.all([
      api.get<{ enabled: boolean; ttl_seconds: number }>("/api/settings/cache"),
      api.get<{ entry_count: number; total_hits: number; total_size_bytes: number }>("/api/cache/stats"),
    ]);
    cacheSettings.value = {
      enabled: settingsRes.data.enabled,
      ttl_seconds: settingsRes.data.ttl_seconds,
    };
    cacheStatsData.value = {
      entry_count: statsRes.data.entry_count,
      total_hits: statsRes.data.total_hits,
      total_size_bytes: statsRes.data.total_size_bytes,
    };
  } catch (err: any) {
    message.error(err?.response?.data?.error ?? t("settings.errors.loadCache"));
  }
}

async function saveCache() {
  savingCache.value = true;
  try {
    await api.put("/api/settings/cache", {
      enabled: cacheSettings.value.enabled,
      ttl_seconds: cacheSettings.value.ttl_seconds,
    });
    await loadCache();
    message.success(t("settings.messages.updated"));
  } catch (err: any) {
    message.error(err?.response?.data?.error ?? t("common.saveFailed"));
  } finally {
    savingCache.value = false;
  }
}

async function clearCache() {
  try {
    await api.delete("/api/cache");
    await loadCache();
    message.success(t("settings.messages.updated"));
  } catch (err: any) {
    message.error(err?.response?.data?.error ?? t("common.deleteFailed"));
  }
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, i);
  return `${value.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

async function copy() {
  try {
    await writeClipboardText(masterKey.value);
    message.success(t("common.copiedToClipboard"));
  } catch {
    message.error(t("common.copyFailed"));
  }
}

async function resetKey() {
  try {
    const { data } = await api.post<{ master_key: string }>(
      "/api/settings/master-key/reset"
    );
    masterKey.value = data.master_key;
    storeMasterKey(masterKey.value);
    message.success(t("settings.messages.masterKeyReset"));
  } catch (err: any) {
    message.error(err?.response?.data?.error ?? t("common.resetFailed"));
  }
}

onMounted(async () => {
  await load();
  await loadAutoSync();
  await loadLogCleanup();
  await loadCache();
});
</script>

<style scoped>
.page-header {
  margin-bottom: 8px;
}

.header-info {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.page-title {
  margin: 0;
  font-size: 24px;
  font-weight: 700;
}

.page-subtitle {
  color: #888;
  font-size: 14px;
}

.settings-card {
  border-radius: 12px;
  height: 100%;
}

.field-label {
  font-size: 14px;
  font-weight: 500;
  margin-bottom: 8px;
  color: #666;
}

.sync-stats {
  background: rgba(0, 0, 0, 0.02);
  padding: 12px;
  border-radius: 8px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.sync-stat-item {
  display: flex;
  justify-content: space-between;
  font-size: 13px;
}

.sync-stat-item .label {
  color: #888;
}

.sync-stat-item .value {
  font-family: monospace;
  font-weight: 500;
}

.sync-stat-item .value.success {
  color: #18a058;
}

.error-alert {
  margin-top: 8px;
}
</style>
