<template>
  <div>
    <!-- Loading state -->
    <div v-if="!data && loading" class="dash-loading">
      <div class="skeleton" style="width: 120px; height: 28px;"></div>
    </div>

    <template v-if="data">
      <!-- Stat cards -->
      <div class="stat-grid">
        <div class="stat-card">
          <div class="stat-icon bg-blue">🖥️</div>
          <div class="stat-body">
            <div class="stat-value">{{ data.nodes.total }}</div>
            <div class="stat-label">节点总数</div>
          </div>
        </div>
        <div class="stat-card">
          <div class="stat-icon bg-green">✅</div>
          <div class="stat-body">
            <div class="stat-value text-green">{{ data.nodes.online }}</div>
            <div class="stat-label">在线节点</div>
          </div>
        </div>
        <div class="stat-card">
          <div class="stat-icon bg-purple">🔀</div>
          <div class="stat-body">
            <div class="stat-value">{{ data.rules.total }}</div>
            <div class="stat-label">转发规则</div>
          </div>
        </div>
        <div class="stat-card">
          <div class="stat-icon bg-indigo">▶️</div>
          <div class="stat-body">
            <div class="stat-value text-green">{{ data.rules.running }}</div>
            <div class="stat-label">运行中</div>
          </div>
        </div>
      </div>

      <!-- Info row -->
      <div class="info-grid">
        <div class="card info-card">
          <div class="card-header">
            <h3 class="card-title">节点状态分布</h3>
          </div>
          <div class="status-bars">
            <div class="status-bar-row">
              <span class="status-bar-dot dot-green"></span>
              <span class="status-bar-label">在线</span>
              <div class="status-bar-track"><div class="status-bar-fill bg-green" :style="{ width: pct(data.nodes.online, data.nodes.total) + '%' }"></div></div>
              <span class="status-bar-value">{{ data.nodes.online }}</span>
            </div>
            <div class="status-bar-row">
              <span class="status-bar-dot dot-gray"></span>
              <span class="status-bar-label">离线</span>
              <div class="status-bar-track"><div class="status-bar-fill bg-gray" :style="{ width: pct(data.nodes.offline, data.nodes.total) + '%' }"></div></div>
              <span class="status-bar-value">{{ data.nodes.offline }}</span>
            </div>
            <div class="status-bar-row">
              <span class="status-bar-dot dot-yellow"></span>
              <span class="status-bar-label">禁用</span>
              <div class="status-bar-track"><div class="status-bar-fill bg-yellow" :style="{ width: pct(data.nodes.disabled, data.nodes.total) + '%' }"></div></div>
              <span class="status-bar-value">{{ data.nodes.disabled }}</span>
            </div>
          </div>
        </div>

        <div class="card info-card">
          <div class="card-header">
            <h3 class="card-title">今日流量</h3>
          </div>
          <div class="traffic-body">
            <div class="traffic-row">
              <span class="traffic-arrow traffic-down">↓</span>
              <span class="traffic-value">{{ formatBytes(data.traffic_today.bytes_in) }}</span>
              <span class="traffic-label">入站</span>
            </div>
            <div class="traffic-row">
              <span class="traffic-arrow traffic-up">↑</span>
              <span class="traffic-value">{{ formatBytes(data.traffic_today.bytes_out) }}</span>
              <span class="traffic-label">出站</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Recent tables -->
      <div class="info-grid">
        <div class="card info-card">
          <div class="card-header">
            <h3 class="card-title">最近心跳</h3>
          </div>
          <div v-if="!data.recent_heartbeats?.length" class="empty-inline">暂无数据</div>
          <table v-else class="data-table">
            <tbody>
              <tr v-for="h in data.recent_heartbeats.slice(0, 6)" :key="h.node_id">
                <td style="font-weight: 500;">{{ h.name || h.node_id }}</td>
                <td style="text-align: right; color: var(--color-text-muted); font-size: 0.75rem;">{{ h.last_heartbeat_at || '-' }}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="card info-card">
          <div class="card-header">
            <h3 class="card-title">失败任务</h3>
          </div>
          <div v-if="!data.recent_failed_tasks?.length" class="empty-inline text-green">🎉 暂无失败任务</div>
          <table v-else class="data-table">
            <tbody>
              <tr v-for="t in data.recent_failed_tasks.slice(0, 6)" :key="t.task_id">
                <td style="font-weight: 500;">{{ t.type }}</td>
                <td style="color: var(--color-text-muted); font-size: 0.75rem;">{{ t.node_id }}</td>
                <td style="text-align: right;"><span class="badge badge-danger">{{ t.status }}</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { dashboardApi } from '@/api/modules'

const data = ref<any>(null)
const loading = ref(true)

onMounted(async () => {
  try {
    const res = await dashboardApi.get()
    data.value = res.data.data
  } catch { /* stay null */ }
  loading.value = false
})

function formatBytes(bytes: number) {
  if (!bytes) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return (bytes / Math.pow(k, i)).toFixed(1) + ' ' + sizes[i]
}

function pct(val: number, total: number) {
  if (!total) return 0
  return Math.round((val / total) * 100)
}
</script>

<style scoped>
.dash-loading { padding: 2rem 0; }

.stat-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 1rem;
  margin-bottom: 1.5rem;
}
.stat-card {
  background: white;
  border-radius: 14px;
  padding: 1.25rem;
  box-shadow: var(--shadow-sm);
  border: 1px solid var(--color-border);
  display: flex;
  align-items: center;
  gap: 1rem;
  transition: box-shadow 0.15s;
}
.stat-card:hover { box-shadow: var(--shadow-md); }
.stat-icon {
  width: 48px;
  height: 48px;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.25rem;
  flex-shrink: 0;
}
.bg-blue { background: #dbeafe; }
.bg-green { background: #dcfce7; }
.bg-purple { background: #ede9fe; }
.bg-indigo { background: #e0e7ff; }
.bg-gray { background: #f1f5f9; }
.bg-yellow { background: #fef3c7; }

.stat-value { font-size: 1.75rem; font-weight: 700; line-height: 1; color: #1e293b; }
.text-green { color: #16a34a; }
.stat-label { font-size: 0.75rem; color: var(--color-text-muted); margin-top: 0.25rem; }

.info-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
  gap: 1rem;
  margin-bottom: 1rem;
}
.info-card { padding: 1.25rem; }
.card-header { margin-bottom: 1rem; }
.card-title {
  font-size: 0.875rem;
  font-weight: 600;
  color: var(--color-text-primary);
  margin: 0;
}

.status-bars { display: flex; flex-direction: column; gap: 0.625rem; }
.status-bar-row {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.8125rem;
}
.status-bar-label { width: 36px; color: var(--color-text-secondary); }
.status-bar-track {
  flex: 1;
  height: 8px;
  background: #f1f5f9;
  border-radius: 4px;
  overflow: hidden;
}
.status-bar-fill { height: 100%; border-radius: 4px; transition: width 0.4s ease; }
.status-bar-value { width: 24px; text-align: right; font-weight: 600; font-variant-numeric: tabular-nums; }

.traffic-body { display: flex; flex-direction: column; gap: 0.75rem; }
.traffic-row {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.875rem;
}
.traffic-arrow { font-size: 1rem; font-weight: 700; }
.traffic-down { color: #3b82f6; }
.traffic-up { color: #8b5cf6; }
.traffic-value { font-weight: 600; font-variant-numeric: tabular-nums; }
.traffic-label { color: var(--color-text-muted); font-size: 0.75rem; }

.empty-inline {
  font-size: 0.8125rem;
  color: var(--color-text-muted);
  padding: 0.5rem 0;
}
</style>
