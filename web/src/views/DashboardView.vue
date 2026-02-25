<template>
  <n-space vertical size="large">
    <div class="page-header">
      <h2 class="page-title">{{ t("dashboard.title") }}</h2>
      <n-button
        size="small"
        @click="refreshAll"
        :loading="loadingStats || loadingChart"
        type="primary"
        secondary
      >
        <template #icon>
          <n-icon :component="RefreshOutline" />
        </template>
        {{ t("dashboard.refreshData") }}
      </n-button>
    </div>

    <n-grid cols="1 s:2 m:5" responsive="screen" :x-gap="12" :y-gap="12">
      <n-gi>
        <n-card size="small" class="stat-card">
          <n-statistic
            :label="t('dashboard.stats.remainingQuota')"
            :value="stats?.total_remaining ?? 0"
          >
            <template #prefix>
              <n-icon :component="BatteryFullOutline" color="#10b981" />
            </template>
          </n-statistic>
        </n-card>
      </n-gi>
      <n-gi>
        <n-card size="small" class="stat-card">
          <n-statistic
            :label="t('dashboard.stats.totalUsed')"
            :value="stats?.total_used ?? 0"
          >
            <template #prefix>
              <n-icon :component="CloudUploadOutline" color="#6366f1" />
            </template>
          </n-statistic>
        </n-card>
      </n-gi>
      <n-gi>
        <n-card size="small" class="stat-card">
          <n-statistic
            :label="t('dashboard.stats.activeKeys')"
            :value="stats?.active_key_count ?? 0"
          >
            <template #suffix>
              <span style="font-size: 14px; color: #999"
                >/ {{ stats?.key_count ?? 0 }}</span
              >
            </template>
            <template #prefix>
              <n-icon :component="KeyOutline" color="#f59e0b" />
            </template>
          </n-statistic>
        </n-card>
      </n-gi>
      <n-gi>
        <n-card size="small" class="stat-card">
          <n-statistic
            :label="t('dashboard.stats.todayRequests')"
            :value="stats?.today_requests ?? 0"
          >
            <template #prefix>
              <n-icon :component="PulseOutline" color="#ef4444" />
            </template>
          </n-statistic>
        </n-card>
      </n-gi>
      <n-gi>
        <n-card size="small" class="stat-card">
          <n-statistic
            :label="t('dashboard.stats.cacheHits')"
            :value="cacheStats?.total_hits ?? 0"
          >
            <template #prefix>
              <n-icon :component="ServerOutline" color="#8b5cf6" />
            </template>
          </n-statistic>
        </n-card>
      </n-gi>
    </n-grid>

    <n-card :title="t('dashboard.resourceUsage.title')" size="small" class="usage-card">
      <template #header-extra>
        <n-tag
          :type="
            usagePercent > 90
              ? 'error'
              : usagePercent > 70
              ? 'warning'
              : 'success'
          "
          round
          size="small"
        >
          {{ t("dashboard.resourceUsage.usedPct", { pct: usagePercent }) }}
        </n-tag>
      </template>
      <div class="usage-content">
        <div class="usage-info">
          <span class="usage-label">{{
            t("dashboard.resourceUsage.monthlyQuotaConsumption")
          }}</span>
          <span class="usage-value"
            >{{ stats?.total_used ?? 0 }} <span class="separator">/</span>
            {{ stats?.total_quota ?? 0 }}</span
          >
        </div>
        <n-progress
          type="line"
          :percentage="usagePercent"
          :indicator-placement="'inside'"
          processing
          :status="
            usagePercent > 90
              ? 'error'
              : usagePercent > 70
              ? 'warning'
              : 'success'
          "
          :height="18"
          border-radius="12px"
        />
      </div>
    </n-card>

    <n-card :title="t('dashboard.requestAnalytics.title')" size="small">
      <template #header-extra>
        <n-tabs
          v-model:value="granularity"
          type="segment"
          size="small"
          class="chart-tabs"
        >
          <n-tab-pane name="hour" :tab="t('dashboard.requestAnalytics.hour')" />
          <n-tab-pane name="day" :tab="t('dashboard.requestAnalytics.day')" />
          <n-tab-pane name="month" :tab="t('dashboard.requestAnalytics.month')" />
        </n-tabs>
      </template>
      <div ref="chartEl" style="height: 350px; width: 100%" />
    </n-card>
  </n-space>
</template>

<script setup lang="ts">
import {
  computed,
  nextTick,
  onBeforeUnmount,
  onMounted,
  ref,
  watch,
} from "vue";
import * as echarts from "echarts";
import {
  NButton,
  NCard,
  NGi,
  NGrid,
  NIcon,
  NProgress,
  NSpace,
  NStatistic,
  NTabPane,
  NTabs,
  NTag,
  useMessage,
} from "naive-ui";
import {
  BatteryFullOutline,
  CloudUploadOutline,
  KeyOutline,
  PulseOutline,
  RefreshOutline,
  ServerOutline,
} from "@vicons/ionicons5";
import { api } from "../api/client";
import type { Stats, TimeSeries } from "../types";
import { locale, t } from "../i18n";

const props = defineProps<{
  refreshNonce?: number;
}>();

const message = useMessage();
const loadingStats = ref(false);
const loadingChart = ref(false);
const stats = ref<Stats | null>(null);
const cacheStats = ref<{ enabled: boolean; entry_count: number; total_hits: number; total_size_bytes: number } | null>(null);
const timeseries = ref<TimeSeries | null>(null);
const granularity = ref<"hour" | "day" | "month">("hour");

const chartEl = ref<HTMLDivElement | null>(null);
let chart: echarts.ECharts | null = null;

const usagePercent = computed(() => {
  if (!stats.value) return 0;
  const total = stats.value.total_quota || 0;
  const used = stats.value.total_used || 0;
  if (total <= 0) return 0;
  return Math.max(0, Math.min(100, Math.round((used / total) * 100)));
});

async function refreshStats() {
  loadingStats.value = true;
  try {
    const [statsRes, cacheRes] = await Promise.all([
      api.get<Stats>("/api/stats"),
      api.get<{ enabled: boolean; entry_count: number; total_hits: number; total_size_bytes: number }>("/api/cache/stats"),
    ]);
    stats.value = statsRes.data;
    cacheStats.value = cacheRes.data;
  } catch (err: any) {
    message.error(err?.response?.data?.error ?? t("dashboard.errors.loadStats"));
  } finally {
    loadingStats.value = false;
  }
}

async function refreshTimeSeries() {
  loadingChart.value = true;
  try {
    const { data } = await api.get<TimeSeries>("/api/stats/timeseries", {
      params: { granularity: granularity.value },
    });
    timeseries.value = data;
    renderChart();
  } catch (err: any) {
    message.error(err?.response?.data?.error ?? t("dashboard.errors.loadChart"));
  } finally {
    loadingChart.value = false;
  }
}

function ensureChart() {
  if (!chartEl.value) return;
  if (chart) return;
  chart = echarts.init(chartEl.value);
  window.addEventListener("resize", onResize);
}

function onResize() {
  chart?.resize();
}

function localizeSeriesName(name: string): string {
  if (name === "All Requests") return t("dashboard.timeseries.allRequests");
  if (name === "Search") return t("dashboard.timeseries.search");
  return name;
}

function renderChart() {
  ensureChart();
  if (!chart || !timeseries.value) return;

  const ts = timeseries.value;
  const isDark =
    document.documentElement.classList.contains("dark") ||
    localStorage.getItem("theme") === "dark";

  chart.setOption(
    {
      backgroundColor: "transparent",
      tooltip: {
        trigger: "axis",
        backgroundColor: isDark ? "#2c2c32" : "#ffffff",
        borderColor: isDark ? "#333" : "#eee",
        textStyle: { color: isDark ? "#eee" : "#333" },
      },
      legend: {
        data: ts.series.map((s) => localizeSeriesName(s.name)),
        textStyle: { color: isDark ? "#ccc" : "#666" },
        bottom: 0,
      },
      grid: { left: 40, right: 16, top: 30, bottom: 60, containLabel: true },
      xAxis: {
        type: "category",
        data: ts.labels,
        axisLine: { lineStyle: { color: isDark ? "#444" : "#eee" } },
        axisLabel: { color: isDark ? "#888" : "#999" },
      },
      yAxis: {
        type: "value",
        minInterval: 1,
        splitLine: { lineStyle: { color: isDark ? "#333" : "#f5f5f5" } },
        axisLabel: { color: isDark ? "#888" : "#999" },
      },
      series: ts.series.map((s, idx) => {
        const colors = [
          ["#6366f1", "#818cf8"],
          ["#10b981", "#34d399"],
        ];
        const color = colors[idx % colors.length];
        return {
          name: localizeSeriesName(s.name),
          type: "bar",
          stack: "total",
          barWidth: "60%",
          itemStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: color[1] },
              { offset: 1, color: color[0] },
            ]),
            borderRadius: [4, 4, 0, 0],
          },
          data: s.data,
        };
      }),
    },
    { notMerge: true }
  );
}

async function refreshAll() {
  await refreshStats();
  await refreshTimeSeries();
}

watch(
  () => props.refreshNonce,
  async (value, previous) => {
    if (value === undefined || previous === undefined) return;
    if (value === previous) return;
    await nextTick();
    await refreshAll();
  }
);

watch(granularity, async () => {
  await nextTick();
  await refreshTimeSeries();
});

watch(locale, async () => {
  await nextTick();
  renderChart();
});

onMounted(async () => {
  await refreshStats();
  await nextTick();
  ensureChart();
  await refreshTimeSeries();
});

onBeforeUnmount(() => {
  window.removeEventListener("resize", onResize);
  chart?.dispose();
  chart = null;
});
</script>

<style scoped>
.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 4px;
}

.page-title {
  margin: 0;
  font-size: 20px;
  font-weight: 700;
}

.stat-card {
  transition: transform 0.2s, box-shadow 0.2s;
}

.stat-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
}

.usage-card {
  margin-top: 4px;
}

.usage-content {
  padding: 4px 0;
}

.usage-info {
  display: flex;
  justify-content: space-between;
  align-items: flex-end;
  margin-bottom: 8px;
}

.usage-label {
  font-size: 13px;
  color: #888;
}

.usage-value {
  font-size: 18px;
  font-weight: 600;
  font-family: monospace;
}

.separator {
  color: #ccc;
  margin: 0 4px;
  font-weight: 400;
}

.chart-tabs {
  width: 200px;
}
</style>
