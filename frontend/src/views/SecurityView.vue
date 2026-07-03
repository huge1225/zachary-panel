<template>
  <div class="bg-white rounded-lg p-5 shadow-sm">
    <h2 class="text-lg font-semibold mb-4">安全事件</h2>
    <table class="w-full text-sm">
      <thead>
        <tr class="text-left text-slate-500 border-b">
          <th class="pb-2">时间</th>
          <th class="pb-2">级别</th>
          <th class="pb-2">类型</th>
          <th class="pb-2">节点</th>
          <th class="pb-2">消息</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="e in events" :key="e.id" class="border-b last:border-0">
          <td class="py-2.5 text-slate-400 text-xs">{{ e.created_at }}</td>
          <td class="py-2.5">
            <span :class="severityClass(e.severity)" class="px-2 py-0.5 rounded text-xs">{{ e.severity }}</span>
          </td>
          <td class="py-2.5">{{ e.event_type }}</td>
          <td class="py-2.5 font-mono text-xs text-slate-400">{{ e.node_id || '-' }}</td>
          <td class="py-2.5 text-xs">{{ e.message }}</td>
        </tr>
      </tbody>
    </table>
    <div v-if="!events.length" class="text-center text-slate-400 py-10">暂无安全事件 🎉</div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { securityApi } from '@/api/modules'

const events = ref<any[]>([])

onMounted(async () => {
  const res = await securityApi.list({ page_size: 50 })
  events.value = res.data.data?.items || []
})

function severityClass(s: string) {
  switch (s) {
    case 'critical': return 'bg-red-100 text-red-700'
    case 'warning': return 'bg-yellow-100 text-yellow-700'
    default: return 'bg-blue-100 text-blue-700'
  }
}
</script>
