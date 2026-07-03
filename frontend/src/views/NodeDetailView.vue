<template>
  <div class="bg-white rounded-lg p-5 shadow-sm">
    <div v-if="node">
      <div class="flex items-center justify-between mb-4">
        <h2 class="text-lg font-semibold">{{ node.name }}</h2>
        <span :class="statusClass(node.status)" class="px-2 py-0.5 rounded text-xs">{{ node.status }}</span>
      </div>
      <div class="grid grid-cols-2 gap-4 text-sm">
        <DetailItem label="Node ID" :value="node.node_id" mono />
        <DetailItem label="公网 IP" :value="node.public_ip || '-'" />
        <DetailItem label="操作系统" :value="node.os || '-'" />
        <DetailItem label="架构" :value="node.arch || '-'" />
        <DetailItem label="Agent 版本" :value="node.agent_version || '-'" />
        <DetailItem label="nftables" :value="node.nft_status" />
        <DetailItem label="gost" :value="node.gost_status" />
        <DetailItem label="最后心跳" :value="node.last_heartbeat_at || '-'" />
        <DetailItem label="最后 IP" :value="node.last_ip || '-'" />
        <DetailItem label="创建时间" :value="node.created_at || '-'" />
      </div>
      <div v-if="node.remark" class="mt-4 text-sm text-slate-500">备注: {{ node.remark }}</div>
    </div>
    <div v-else class="text-slate-400">加载中...</div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { nodesApi } from '@/api/modules'

const route = useRoute()
const node = ref<any>(null)

onMounted(async () => {
  const id = Number(route.params.id)
  const res = await nodesApi.get(id)
  node.value = res.data.data
})

function statusClass(status: string) {
  switch (status) {
    case 'online': return 'bg-green-100 text-green-700'
    case 'offline': return 'bg-slate-100 text-slate-500'
    case 'disabled': return 'bg-yellow-100 text-yellow-700'
    case 'error': return 'bg-red-100 text-red-700'
    default: return 'bg-slate-100 text-slate-500'
  }
}
</script>

<script lang="ts">
// DetailItem component
</script>
