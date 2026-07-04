<template>
  <div class="bg-white rounded-lg p-5 shadow-sm">
    <div class="flex items-center justify-between mb-4">
      <h2 class="text-lg font-semibold">节点管理</h2>
      <button @click="showCreate = true" class="bg-blue-600 text-white text-sm px-3 py-1.5 rounded-lg hover:bg-blue-700">+ 添加节点</button>
    </div>

    <table class="w-full text-sm">
      <thead>
        <tr class="text-left text-slate-500 border-b">
          <th class="pb-2">名称</th>
          <th class="pb-2">Node ID</th>
          <th class="pb-2">状态</th>
          <th class="pb-2">IP</th>
          <th class="pb-2">最后心跳</th>
          <th class="pb-2">操作</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="n in nodes" :key="n.node_id" class="border-b last:border-0 hover:bg-slate-50">
          <td class="py-2.5 font-medium">{{ n.name }}</td>
          <td class="py-2.5 text-slate-400 font-mono text-xs">{{ n.node_id }}</td>
          <td class="py-2.5">
            <span :class="statusClass(n.status)" class="px-2 py-0.5 rounded text-xs">{{ n.status }}</span>
          </td>
          <td class="py-2.5 text-slate-400">{{ n.public_ip || n.last_ip || '-' }}</td>
          <td class="py-2.5 text-slate-400 text-xs">{{ n.last_heartbeat_at || '-' }}</td>
          <td class="py-2.5">
            <router-link :to="`/nodes/${n.id}`" class="text-blue-600 hover:underline text-xs mr-2">详情</router-link>
            <button @click="getInstallCmd(n.id)" class="text-blue-600 hover:underline text-xs">安装命令</button>
          </td>
        </tr>
      </tbody>
    </table>

    <!-- Create Modal -->
    <div v-if="showCreate" class="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
      <div class="bg-white rounded-lg p-6 w-full max-w-md">
        <h3 class="text-lg font-semibold mb-4">添加节点</h3>
        <div class="space-y-3">
          <input v-model="form.name" placeholder="节点名称" class="w-full border rounded px-3 py-2 text-sm" />
          <input v-model="form.public_ip" placeholder="公网 IP（可选）" class="w-full border rounded px-3 py-2 text-sm" />
          <input v-model="form.remark" placeholder="备注（可选）" class="w-full border rounded px-3 py-2 text-sm" />
        </div>
        <div class="flex justify-end gap-2 mt-4">
          <button @click="showCreate = false" class="px-4 py-2 text-sm rounded border">取消</button>
          <button @click="createNode" class="px-4 py-2 text-sm rounded bg-blue-600 text-white">创建</button>
        </div>
      </div>
    </div>

    <!-- Install Command Modal -->
    <div v-if="installCmd" class="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
      <div class="bg-white rounded-lg p-6 w-full max-w-lg">
        <h3 class="text-lg font-semibold mb-2">安装命令</h3>
        <p class="text-sm text-slate-500 mb-3">在目标节点上执行此命令</p>
        <div class="relative">
          <pre class="bg-slate-900 text-green-400 rounded p-3 text-sm overflow-x-auto pr-12">{{ installCmd }}</pre>
          <button @click="copyInstallCmd" class="absolute top-2 right-2 bg-slate-700 hover:bg-slate-600 text-white text-xs px-2 py-1 rounded">{{ copyBtnText }}</button>
        </div>
        <div class="flex justify-end mt-4">
          <button @click="installCmd = ''" class="px-4 py-2 text-sm rounded bg-blue-600 text-white">关闭</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { nodesApi } from '@/api/modules'

const nodes = ref<any[]>([])
const showCreate = ref(false)
const installCmd = ref('')
const form = ref({ name: '', public_ip: '', remark: '' })
const copyBtnText = ref('复制')

onMounted(load)

async function load() {
  const res = await nodesApi.list({ page_size: 100 })
  nodes.value = res.data.data?.items || []
}

async function createNode() {
  await nodesApi.create(form.value)
  showCreate.value = false
  form.value = { name: '', public_ip: '', remark: '' }
  await load()
}

async function getInstallCmd(id: number) {
  const res = await nodesApi.installCommand(id)
  installCmd.value = res.data.data?.command || ''
}

async function copyInstallCmd() {
  try {
    await navigator.clipboard.writeText(installCmd.value)
    copyBtnText.value = '已复制'
    setTimeout(() => copyBtnText.value = '复制', 2000)
  } catch {
    // Fallback for non-secure contexts
    const ta = document.createElement('textarea')
    ta.value = installCmd.value
    document.body.appendChild(ta)
    ta.select()
    document.execCommand('copy')
    document.body.removeChild(ta)
    copyBtnText.value = '已复制'
    setTimeout(() => copyBtnText.value = '复制', 2000)
  }
}

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
