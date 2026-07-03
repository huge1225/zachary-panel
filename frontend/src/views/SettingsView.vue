<template>
  <div class="bg-white rounded-lg p-5 shadow-sm max-w-2xl">
    <h2 class="text-lg font-semibold mb-4">系统设置</h2>
    <div class="space-y-4 text-sm">
      <div class="p-3 bg-slate-50 rounded">
        <p class="font-medium">API 信息</p>
        <p class="text-slate-400 mt-1">API Base: <code class="bg-slate-200 px-1 rounded">/api</code></p>
        <p class="text-slate-400">Agent WS: <code class="bg-slate-200 px-1 rounded">/ws/agent</code></p>
      </div>
      <div class="p-3 bg-slate-50 rounded">
        <p class="font-medium">JWT Token</p>
        <p class="text-slate-400 mt-1 font-mono text-xs break-all">{{ token || '-' }}</p>
      </div>
      <div class="p-3 bg-slate-50 rounded">
        <p class="font-medium">用户</p>
        <p class="text-slate-400 mt-1">{{ auth.username }}</p>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useAuthStore } from '@/stores/auth'
const auth = useAuthStore()
const token = auth.token
</script>
