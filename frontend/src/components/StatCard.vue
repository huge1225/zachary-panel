<template>
  <div class="stat-card-mini">
    <div class="stat-icon-wrap" :class="iconBg">
      <span>{{ icon }}</span>
    </div>
    <div class="stat-info">
      <div class="stat-num" :class="colorClass">{{ value }}</div>
      <div class="stat-text">{{ title }}</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ title: string; value: number; icon: string; color?: string }>()

const colorClass = computed(() => {
  switch (props.color) {
    case 'green': return 'text-green-600'
    case 'red': return 'text-red-600'
    case 'yellow': return 'text-yellow-600'
    default: return 'text-slate-800'
  }
})

const iconBg = computed(() => {
  switch (props.color) {
    case 'green': return 'bg-green-50'
    default: return 'bg-blue-50'
  }
})
</script>

<style scoped>
.stat-card-mini {
  background: white;
  border-radius: 14px;
  padding: 1.25rem;
  box-shadow: 0 1px 3px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.04);
  border: 1px solid #e2e8f0;
  display: flex;
  align-items: center;
  gap: 1rem;
  transition: box-shadow 0.15s;
}
.stat-card-mini:hover {
  box-shadow: 0 4px 6px -1px rgba(0,0,0,0.07), 0 2px 4px -2px rgba(0,0,0,0.04);
}
.stat-icon-wrap {
  width: 48px;
  height: 48px;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.25rem;
  flex-shrink: 0;
}
.stat-num { font-size: 1.75rem; font-weight: 700; line-height: 1; }
.stat-text { font-size: 0.75rem; color: #94a3b8; margin-top: 0.25rem; }
</style>
