<template>
  <div class="bg-white rounded-lg p-5 shadow-sm">
    <div class="flex items-center justify-between mb-4">
      <h2 class="text-lg font-semibold">转发规则</h2>
      <router-link to="/rules/create" class="bg-blue-600 text-white text-sm px-3 py-1.5 rounded-lg hover:bg-blue-700">+ 创建规则</router-link>
    </div>

    <table class="w-full text-sm">
      <thead>
        <tr class="text-left text-slate-500 border-b">
          <th class="pb-2">名称</th>
          <th class="pb-2">模式</th>
          <th class="pb-2">协议</th>
          <th class="pb-2">监听</th>
          <th class="pb-2">目标</th>
          <th class="pb-2">状态</th>
          <th class="pb-2">操作</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="r in rules" :key="r.id" class="border-b last:border-0 hover:bg-slate-50">
          <td class="py-2.5 font-medium">{{ r.name }}</td>
          <td class="py-2.5"><span class="px-1.5 py-0.5 rounded text-xs bg-slate-100">{{ r.mode }}</span></td>
          <td class="py-2.5 text-slate-500">{{ r.protocol }}</td>
          <td class="py-2.5 font-mono text-xs">{{ r.listen_addr }}:{{ r.listen_port }}</td>
          <td class="py-2.5 font-mono text-xs">{{ r.target_addr }}:{{ r.target_port }}</td>
          <td class="py-2.5">
            <span :class="ruleStatusClass(r.status)" class="px-2 py-0.5 rounded text-xs">{{ r.status }}</span>
          </td>
          <td class="py-2.5 flex gap-1">
            <button v-if="r.status !== 'running'" @click="action(r.id, 'start')" class="text-green-600 text-xs hover:underline">启动</button>
            <button v-if="r.status === 'running'" @click="action(r.id, 'stop')" class="text-yellow-600 text-xs hover:underline">停止</button>
            <button @click="action(r.id, 'restart')" class="text-blue-600 text-xs hover:underline">重启</button>
            <router-link :to="`/rules/${r.id}/edit`" class="text-blue-600 text-xs hover:underline ml-1">编辑</router-link>
            <button @click="del(r.id)" class="text-red-600 text-xs hover:underline ml-1">删除</button>
          </td>
        </tr>
      </tbody>
    </table>
    <div v-if="!rules.length" class="text-center text-slate-400 py-10">暂无规则</div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { rulesApi } from '@/api/modules'

const rules = ref<any[]>([])

onMounted(load)

async function load() {
  const res = await rulesApi.list({ page_size: 100 })
  rules.value = res.data.data?.items || []
}

async function action(id: number, act: string) {
  await (rulesApi as any)[act](id)
  await load()
}

async function del(id: number) {
  if (!confirm('确定删除此规则？')) return
  await rulesApi.delete(id)
  await load()
}

function ruleStatusClass(status: string) {
  switch (status) {
    case 'running': return 'bg-green-100 text-green-700'
    case 'stopped': return 'bg-slate-100 text-slate-500'
    case 'failed': return 'bg-red-100 text-red-700'
    default: return 'bg-slate-100 text-slate-500'
  }
}
</script>
