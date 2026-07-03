<template>
  <div>
    <div class="text-slate-400 text-xs">{{ label }}</div>
    <div :class="mono ? 'font-mono text-xs' : ''" class="text-slate-700 mt-0.5">{{ value }}</div>
  </div>
</template>

<script setup lang="ts">
defineProps<{ label: string; value: string; mono?: boolean }>()
</script>
