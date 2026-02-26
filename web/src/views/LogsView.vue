<template>
  <n-space vertical size="large">
    <div class="page-header">
      <div class="header-info">
        <h2 class="page-title">{{ t("logs.title") }}</h2>
        <div class="page-subtitle">
          {{ t("logs.subtitle") }}
        </div>
      </div>
      <n-space align="center" :size="[12, 12]">
        <n-select
          v-model:value="statusCode"
          :options="statusOptions"
          :loading="statusLoading"
          style="width: 200px"
          size="medium"
        />
        <n-button
          :loading="loading"
          :disabled="clearing"
          @click="refresh"
          secondary
        >
          <template #icon>
            <n-icon :component="RefreshOutline" />
          </template>
          {{ t("logs.refreshLogs") }}
        </n-button>
        <n-popconfirm @positive-click="clearLogs">
          <template #trigger>
            <n-button
              type="error"
              secondary
              :loading="clearing"
              :disabled="loading || total === 0"
            >
              <template #icon>
                <n-icon :component="TrashOutline" />
              </template>
              {{ t("logs.clearLogs") }}
            </n-button>
          </template>
          {{ t("logs.confirm.clearLogs") }}
        </n-popconfirm>
      </n-space>
    </div>

    <n-card :bordered="false" class="table-card">
      <n-data-table
        :columns="columns"
        :data="items"
        :loading="loading"
        :row-key="rowKey"
        scroll-x="1000"
        size="small"
      />
      <div class="pagination-container">
        <n-pagination
          v-model:page="page"
          :page-size="pageSize"
          :item-count="total"
          show-size-picker
          :page-sizes="[10, 20, 50, 100]"
        />
      </div>
    </n-card>

    <n-modal
      v-model:show="showDetail"
      preset="card"
      :title="t('logs.detail.title')"
      style="max-width: 1000px"
      class="log-detail-modal"
    >
      <n-space vertical size="large">
        <div class="detail-info-bar">
          <n-descriptions
            bordered
            label-placement="left"
            :column="2"
            size="small"
          >
            <n-descriptions-item :label="t('logs.detail.endpoint')">
              <n-tag :bordered="false" type="info" size="small">{{
                selected?.endpoint || "-"
              }}</n-tag>
            </n-descriptions-item>
            <n-descriptions-item :label="t('logs.detail.status')">
              <n-tag
                :bordered="false"
                :type="
                  selected?.status_code === 200
                    ? 'success'
                    : selected?.status_code === 0
                      ? 'warning'
                      : 'error'
                "
                size="small"
              >
                {{ selected?.status_code ?? "-" }}
              </n-tag>
            </n-descriptions-item>
            <n-descriptions-item :label="t('logs.detail.clientIp')">
              <code>{{ selected?.client_ip }}</code>
            </n-descriptions-item>
            <n-descriptions-item :label="t('logs.detail.latency')">
              {{ selected?.latency }} ms
            </n-descriptions-item>
            <n-descriptions-item :label="t('logs.detail.keyUsed')" :span="2">
              {{ selected?.key_alias || "-" }}
            </n-descriptions-item>
          </n-descriptions>
        </div>

        <n-tabs type="segment" animated>
          <n-tab-pane name="request" :tab="t('logs.detail.requestBody')">
            <div class="json-container">
              <n-button
                quaternary
                circle
                size="tiny"
                class="copy-btn"
                @click="copyToClipboard(selected?.request_body)"
              >
                <template #icon><n-icon :component="CopyOutline" /></template>
              </n-button>
              <n-input
                type="textarea"
                :value="prettyJson(selected?.request_body)"
                readonly
                :autosize="{ minRows: 10, maxRows: 25 }"
                class="json-textarea"
              />
            </div>
          </n-tab-pane>
          <n-tab-pane name="response" :tab="t('logs.detail.responseBody')">
            <div class="json-container">
              <n-button
                quaternary
                circle
                size="tiny"
                class="copy-btn"
                @click="copyToClipboard(selected?.response_body)"
              >
                <template #icon><n-icon :component="CopyOutline" /></template>
              </n-button>
              <n-input
                type="textarea"
                :value="prettyJson(selected?.response_body)"
                readonly
                :autosize="{ minRows: 10, maxRows: 25 }"
                class="json-textarea"
              />
            </div>
          </n-tab-pane>
        </n-tabs>
      </n-space>

      <template #footer>
        <n-space justify="end">
          <n-button @click="showDetail = false">{{
            t("common.dismiss")
          }}</n-button>
        </n-space>
      </template>
    </n-modal>
  </n-space>
</template>

<script setup lang="ts">
import { computed, h, onMounted, ref, watch } from "vue";
import {
  NButton,
  NCard,
  NDescriptions,
  NDescriptionsItem,
  NDataTable,
  NIcon,
  NInput,
  NModal,
  NPopconfirm,
  NPagination,
  NSelect,
  NSpace,
  NTabPane,
  NTabs,
  NTag,
  NTooltip,
  useMessage,
  type DataTableColumns,
  type SelectOption,
} from "naive-ui";
import {
  CopyOutline,
  EyeOutline,
  RefreshOutline,
  TrashOutline,
} from "@vicons/ionicons5";
import { api } from "../api/client";
import type { LogItem, LogStatusCount } from "../types";
import { writeClipboardText } from "../utils/clipboard";
import { t } from "../i18n";

const message = useMessage();

const items = ref<LogItem[]>([]);
const loading = ref(false);
const clearing = ref(false);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const statusCode = ref<number | "all">("all");
const statusCounts = ref<LogStatusCount[]>([]);
const statusLoading = ref(false);
const showDetail = ref(false);
const selected = ref<LogItem | null>(null);

const statusOptions = computed<SelectOption[]>(() => [
  { label: t("logs.filter.allStatusCodes"), value: "all" },
  ...statusCounts.value.map((item) => ({
    label: `${item.status_code} (${item.count})`,
    value: item.status_code,
  })),
]);

function rowKey(row: LogItem) {
  return row.id;
}

function prettyJson(value?: string | null) {
  if (!value) return "";
  const trimmed = value.trim();
  if (!trimmed) return "";
  try {
    return JSON.stringify(JSON.parse(trimmed), null, 2);
  } catch {
    return value;
  }
}

function formatLogTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(
    date.getDate(),
  )} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(
    date.getSeconds(),
  )}`;
}

async function refreshLogs() {
  loading.value = true;
  try {
    const params: Record<string, any> = {
      page: page.value,
      page_size: pageSize.value,
    };
    if (statusCode.value !== "all") {
      params.status_code = statusCode.value;
    }
    const { data } = await api.get<{ items: LogItem[]; total: number }>(
      "/api/logs",
      {
        params,
      },
    );
    items.value = data.items;
    total.value = data.total;
  } catch (err: any) {
    message.error(err?.response?.data?.error ?? t("logs.errors.loadLogs"));
  } finally {
    loading.value = false;
  }
}

async function loadStatusCounts() {
  statusLoading.value = true;
  try {
    const { data } = await api.get<LogStatusCount[]>("/api/logs/status-codes");
    statusCounts.value = data;

    if (
      statusCode.value !== "all" &&
      !data.some((item) => item.status_code === statusCode.value)
    ) {
      statusCode.value = "all";
    }
  } catch (err: any) {
    message.error(
      err?.response?.data?.error ?? t("logs.errors.loadStatusCodes"),
    );
  } finally {
    statusLoading.value = false;
  }
}

async function refresh() {
  await Promise.all([refreshLogs(), loadStatusCounts()]);
}

async function clearLogs() {
  clearing.value = true;
  try {
    const { data } = await api.delete<{ deleted: number }>("/api/logs");

    showDetail.value = false;
    selected.value = null;

    const previousPage = page.value;
    const previousStatus = statusCode.value;

    statusCode.value = "all";
    page.value = 1;

    await loadStatusCounts();
    if (previousPage === 1 && previousStatus === "all") {
      await refreshLogs();
    }

    message.success(t("logs.messages.clearedLogs", { count: data.deleted }));
  } catch (err: any) {
    message.error(err?.response?.data?.error ?? t("logs.errors.clearLogs"));
  } finally {
    clearing.value = false;
  }
}

async function copyToClipboard(text?: string | null) {
  if (!text) return;
  try {
    await writeClipboardText(text);
    message.success(t("common.copiedToClipboard"));
  } catch {
    message.error(t("common.copyFailed"));
  }
}

watch([page, pageSize], refreshLogs);
watch(statusCode, () => {
  const previousPage = page.value;
  page.value = 1;
  if (previousPage === 1) {
    refreshLogs();
  }
});
onMounted(refresh);

function openDetail(row: LogItem) {
  selected.value = row;
  showDetail.value = true;
}

const columns: DataTableColumns<LogItem> = [
  {
    title: () => t("logs.table.time"),
    key: "created_at",
    width: 180,
    render: (r) =>
      h("span", { class: "time-cell" }, formatLogTime(r.created_at)),
  },
  {
    title: () => t("logs.table.clientIp"),
    key: "client_ip",
    width: 140,
    render: (r) => h("code", { class: "ip-cell" }, r.client_ip),
  },
  {
    title: () => t("logs.table.keyAlias"),
    key: "key_alias",
    width: 150,
    render: (r) => h("div", { class: "alias-cell" }, r.key_alias || "-"),
  },
  {
    title: () => t("logs.table.endpoint"),
    key: "endpoint",
    render: (r) => h("code", { class: "endpoint-cell" }, r.endpoint),
  },
  {
    title: () => t("logs.table.latency"),
    key: "latency",
    width: 100,
    align: "right",
    render: (r) => h("span", { class: "latency-cell" }, `${r.latency}ms`),
  },
  {
    title: () => t("logs.table.status"),
    key: "status_code",
    width: 140,
    align: "center",
    render: (r) => {
      const tags = [
        h(
          NTag,
          {
            type:
              r.status_code === 200
                ? "success"
                : r.status_code === 0
                  ? "warning"
                  : "error",
            size: "small",
            round: true,
            bordered: false,
          },
          { default: () => String(r.status_code) },
        ),
      ];
      if (r.cache_hit) {
        tags.push(
          h(
            NTag,
            {
              type: "info",
              size: "small",
              round: true,
              bordered: false,
              style: "margin-left: 4px",
            },
            { default: () => t("logs.table.cacheHit") },
          ),
        );
      }
      return h("span", {}, tags);
    },
  },
  {
    title: () => t("logs.table.actions"),
    key: "actions",
    width: 100,
    align: "right",
    render: (r) => {
      const hasPayload = Boolean(
        (r.request_body && r.request_body.length) ||
        (r.response_body && r.response_body.length),
      );
      return h(
        NTooltip,
        {},
        {
          trigger: () =>
            h(
              NButton,
              {
                size: "small",
                quaternary: true,
                circle: true,
                disabled: !hasPayload,
                onClick: () => openDetail(r),
              },
              { icon: () => h(NIcon, { component: EyeOutline }) },
            ),
          default: () =>
            hasPayload ? t("common.viewDetails") : t("common.noData"),
        },
      );
    },
  },
];
</script>

<style scoped>
.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.header-info {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.page-title {
  margin: 0;
  font-size: 20px;
  font-weight: 700;
}

.page-subtitle {
  color: #888;
  font-size: 13px;
}

.table-card {
  border-radius: 12px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
}

.table-card :deep(.n-card__content) {
  padding: 0;
}

.pagination-container {
  padding: 12px 16px;
  display: flex;
  justify-content: flex-end;
  border-top: 1px solid rgba(0, 0, 0, 0.05);
}

.table-toolbar {
  padding: 16px 16px 0 16px;
}

.time-cell {
  color: #888;
  font-size: 13px;
}

.ip-cell {
  background: rgba(0, 0, 0, 0.03);
  padding: 2px 4px;
  border-radius: 4px;
  font-size: 12px;
}

.alias-cell {
  font-weight: 600;
}

.endpoint-cell {
  color: #2080f0;
  font-size: 13px;
}

.latency-cell {
  font-family: monospace;
  color: #888;
}

.log-detail-modal {
  border-radius: 16px;
}

.json-container {
  position: relative;
}

.copy-btn {
  position: absolute;
  top: 8px;
  right: 8px;
  z-index: 5;
}

.json-textarea :deep(textarea) {
  font-family: "Fira Code", "Roboto Mono", monospace;
  font-size: 13px;
  line-height: 1.5;
  background-color: rgba(0, 0, 0, 0.02);
}
</style>
