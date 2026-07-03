<template>
  <div class="bg-white rounded-lg p-5 shadow-sm">
    <div class="text-2xl font-bold" :class="colorClass">{{ value }}</div>
    <div class="text-sm text-slate-500 mt-1">{{ icon }} {{ title }}</div>
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
</script>
