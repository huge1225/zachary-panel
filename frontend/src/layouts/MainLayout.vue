<template>
  <div class="flex h-screen">
    <!-- Sidebar -->
    <aside class="w-60 bg-slate-800 text-white flex flex-col shrink-0">
      <div class="h-14 flex items-center px-4 border-b border-slate-700">
        <span class="text-lg font-bold">🚀 Zachary Panel</span>
      </div>
      <nav class="flex-1 py-4 space-y-1 px-3">
        <router-link
          v-for="item in menu"
          :key="item.path"
          :to="item.path"
          class="flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors"
          :class="isActive(item.path) ? 'bg-blue-600 text-white' : 'text-slate-300 hover:bg-slate-700'"
        >
          <span>{{ item.icon }}</span>
          <span>{{ item.label }}</span>
        </router-link>
      </nav>
      <div class="p-3 border-t border-slate-700">
        <button
          @click="logout"
          class="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm text-slate-300 hover:bg-red-600/80 transition-colors"
        >
          <span>🚪</span>
          <span>退出登录</span>
        </button>
      </div>
    </aside>

    <!-- Main -->
    <div class="flex-1 flex flex-col overflow-hidden">
      <header class="h-14 bg-white border-b px-6 flex items-center justify-between shrink-0">
        <h1 class="text-base font-semibold text-slate-700">{{ currentTitle }}</h1>
        <span class="text-sm text-slate-500">{{ auth.username }}</span>
      </header>
      <main class="flex-1 overflow-auto p-6">
        <router-view />
      </main>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()

const menu = [
  { path: '/', label: '仪表盘', icon: '📊' },
  { path: '/nodes', label: '节点管理', icon: '🖥️' },
  { path: '/rules', label: '转发规则', icon: '🔀' },
  { path: '/tasks', label: '任务列表', icon: '📋' },
  { path: '/latency', label: '延迟测试', icon: '⏱️' },
  { path: '/security', label: '安全事件', icon: '🛡️' },
  { path: '/settings', label: '系统设置', icon: '⚙️' },
]

const currentTitle = computed(() => {
  const item = menu.find(m => m.path === route.path || (m.path !== '/' && route.path.startsWith(m.path)))
  return item?.label || '仪表盘'
})

function isActive(path: string) {
  if (path === '/') return route.path === '/'
  return route.path.startsWith(path)
}

function logout() {
  auth.logout()
  router.push('/login')
}
</script>
