<template>
  <div class="bg-white rounded-lg p-5 shadow-sm">
    <h2 class="text-lg font-semibold mb-4">任务列表</h2>
    <table class="w-full text-sm">
      <thead>
        <tr class="text-left text-slate-500 border-b">
          <th class="pb-2">类型</th>
          <th class="pb-2">节点</th>
          <th class="pb-2">状态</th>
          <th class="pb-2">结果</th>
          <th class="pb-2">创建时间</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="t in tasks" :key="t.task_id" class="border-b last:border-0 hover:bg-slate-50">
          <td class="py-2.5 font-medium">{{ t.type }}</td>
          <td class="py-2.5 text-slate-400 font-mono text-xs">{{ t.node_id }}</td>
          <td class="py-2.5">
            <span :class="taskStatusClass(t.status)" class="px-2 py-0.5 rounded text-xs">{{ t.status }}</span>
          </td>
          <td class="py-2.5 text-xs max-w-48 truncate">{{ t.message || '-' }}</td>
          <td class="py-2.5 text-slate-400 text-xs">{{ t.created_at }}</td>
        </tr>
      </tbody>
    </table>
    <div v-if="!tasks.length" class="text-center text-slate-400 py-10">暂无任务</div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { tasksApi } from '@/api/modules'

const tasks = ref<any[]>([])

onMounted(async () => {
  const res = await tasksApi.list({ page_size: 100 })
  tasks.value = res.data.data?.items || []
})

function taskStatusClass(status: string) {
  switch (status) {
    case 'pending': return 'bg-yellow-100 text-yellow-700'
    case 'running': return 'bg-blue-100 text-blue-700'
    case 'success': return 'bg-green-100 text-green-700'
    case 'failed': case 'timeout': return 'bg-red-100 text-red-700'
    default: return 'bg-slate-100 text-slate-500'
  }
}
</script>
