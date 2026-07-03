<template>
  <div class="space-y-4">
    <div class="bg-white rounded-lg p-5 shadow-sm">
      <h2 class="text-lg font-semibold mb-4">延迟测试</h2>
      <div class="grid grid-cols-4 gap-3">
        <select v-model="test.node_id" class="border rounded px-3 py-2 text-sm">
          <option value="">所有节点</option>
        </select>
        <select v-model="test.test_type" class="border rounded px-3 py-2 text-sm">
          <option value="tcp">TCP</option>
          <option value="http">HTTP</option>
          <option value="icmp">ICMP</option>
          <option value="dns">DNS</option>
        </select>
        <input v-model="test.target_addr" placeholder="目标地址 *" class="border rounded px-3 py-2 text-sm" />
        <button @click="runTest" class="bg-blue-600 text-white rounded px-3 py-2 text-sm hover:bg-blue-700">开始测试</button>
      </div>
    </div>

    <div class="bg-white rounded-lg p-5 shadow-sm">
      <h3 class="text-sm font-semibold mb-3">测试结果</h3>
      <table class="w-full text-sm">
        <thead>
          <tr class="text-left text-slate-500 border-b">
            <th class="pb-2">目标</th>
            <th class="pb-2">节点</th>
            <th class="pb-2">平均延迟</th>
            <th class="pb-2">丢包率</th>
            <th class="pb-2">状态</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in results" :key="r.test_id" class="border-b last:border-0">
            <td class="py-2">{{ r.target_addr }}:{{ r.target_port }}</td>
            <td class="py-2 font-mono text-xs text-slate-400">{{ r.node_id || '-' }}</td>
            <td class="py-2">{{ r.avg_latency_ms ? r.avg_latency_ms.toFixed(1) + 'ms' : '-' }}</td>
            <td class="py-2">{{ (r.loss_rate * 100).toFixed(1) }}%</td>
            <td class="py-2">
              <span :class="r.status === 'success' ? 'text-green-600' : 'text-red-600'">{{ r.status }}</span>
            </td>
          </tr>
        </tbody>
      </table>
      <div v-if="!results.length" class="text-center text-slate-400 py-10">暂无测试结果</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue'
import { latencyApi } from '@/api/modules'

const test = reactive({ node_id: '', test_type: 'tcp', target_addr: '', target_port: 80 })
const results = ref<any[]>([])

async function runTest() {
  await latencyApi.test(test)
  const res = await latencyApi.list({ page_size: 20 })
  results.value = res.data.data?.items || []
}
</script>
