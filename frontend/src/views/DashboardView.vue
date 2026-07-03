<template>
  <div v-if="data">
    <!-- Stats Cards -->
    <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
      <StatCard title="节点总数" :value="data.nodes.total" icon="🖥️" />
      <StatCard title="在线节点" :value="data.nodes.online" icon="✅" color="green" />
      <StatCard title="转发规则" :value="data.rules.total" icon="🔀" />
      <StatCard title="运行中规则" :value="data.rules.running" icon="▶️" color="green" />
    </div>

    <!-- Info Cards -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
      <div class="bg-white rounded-lg p-5 shadow-sm">
        <h3 class="text-sm font-semibold text-slate-700 mb-3">节点状态</h3>
        <div class="flex gap-4 text-sm">
          <div><span class="inline-block w-2 h-2 rounded-full bg-green-500 mr-1"></span>在线: {{ data.nodes.online }}</div>
          <div><span class="inline-block w-2 h-2 rounded-full bg-slate-400 mr-1"></span>离线: {{ data.nodes.offline }}</div>
          <div><span class="inline-block w-2 h-2 rounded-full bg-yellow-500 mr-1"></span>禁用: {{ data.nodes.disabled }}</div>
        </div>
      </div>
      <div class="bg-white rounded-lg p-5 shadow-sm">
        <h3 class="text-sm font-semibold text-slate-700 mb-3">今日流量</h3>
        <div class="text-sm space-y-1">
          <div>↓ 入站: {{ formatBytes(data.traffic_today.bytes_in) }}</div>
          <div>↑ 出站: {{ formatBytes(data.traffic_today.bytes_out) }}</div>
        </div>
      </div>
    </div>

    <!-- Recent tables -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <div class="bg-white rounded-lg p-5 shadow-sm">
        <h3 class="text-sm font-semibold text-slate-700 mb-3">最近心跳</h3>
        <div v-if="!data.recent_heartbeats?.length" class="text-sm text-slate-400">暂无数据</div>
        <table v-else class="w-full text-sm">
          <tr v-for="h in data.recent_heartbeats.slice(0, 5)" :key="h.node_id" class="border-b last:border-0">
            <td class="py-1.5">{{ h.name || h.node_id }}</td>
            <td class="py-1.5 text-right text-slate-400">{{ h.last_heartbeat_at || '-' }}</td>
          </tr>
        </table>
      </div>
      <div class="bg-white rounded-lg p-5 shadow-sm">
        <h3 class="text-sm font-semibold text-slate-700 mb-3">失败任务</h3>
        <div v-if="!data.recent_failed_tasks?.length" class="text-sm text-green-600">🎉 暂无失败任务</div>
        <table v-else class="w-full text-sm">
          <tr v-for="t in data.recent_failed_tasks.slice(0, 5)" :key="t.task_id" class="border-b last:border-0">
            <td class="py-1.5">{{ t.type }} ({{ t.node_id }})</td>
            <td class="py-1.5 text-right text-red-400">{{ t.status }}</td>
          </tr>
        </table>
      </div>
    </div>
  </div>
  <div v-else class="text-center text-slate-400 py-20">加载中...</div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { dashboardApi } from '@/api/modules'

const data = ref<any>(null)

onMounted(async () => {
  try {
    const res = await dashboardApi.get()
    data.value = res.data.data
  } catch { /* stay null, shows loading */ }
})

function formatBytes(bytes: number) {
  if (!bytes) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return (bytes / Math.pow(k, i)).toFixed(1) + ' ' + sizes[i]
}
</script>
