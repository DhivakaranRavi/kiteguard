<template>
  <div class="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
    <div
      v-for="card in cards"
      :key="card.label"
      class="relative border p-4 flex flex-col gap-2 overflow-hidden panel-glow"
      :class="card.classes"
    >
      <!-- corner marks -->
      <span class="absolute top-0.5 left-1  text-xs opacity-25">┌</span>
      <span class="absolute top-0.5 right-1 text-xs opacity-25">┐</span>
      <span class="absolute bottom-0.5 left-1  text-xs opacity-25">└</span>
      <span class="absolute bottom-0.5 right-1 text-xs opacity-25">┘</span>

      <span class="text-xs tracking-widest uppercase opacity-60 mt-1">[ {{ card.label }} ]</span>
      <span class="font-vt text-5xl leading-none tabular-nums" :class="card.valClass">{{ card.value }}</span>
      <span class="text-xs opacity-35 tracking-wider">{{ card.sub }}</span>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  stats: { type: Object, default: () => ({}) }
})

const cards = computed(() => [
  {
    label: 'Total Events',
    value: props.stats.total ?? '---',
    sub: '// all time',
    classes: 'border-retro-green bg-retro-green-dim text-retro-green',
    valClass: 'text-retro-green glow-green',
  },
  {
    label: 'Blocked',
    value: props.stats.blocks ?? '---',
    sub: '// threats stopped',
    classes: 'border-retro-red bg-retro-red-dim text-retro-red',
    valClass: 'text-retro-red glow-red',
  },
  {
    label: 'Allowed',
    value: props.stats.allows ?? '---',
    sub: '// clean passes',
    classes: 'border-retro-green bg-retro-green-dim text-retro-green',
    valClass: 'text-retro-green glow-green',
  },
  {
    label: 'Today',
    value: props.stats.today ?? '---',
    sub: `// ${new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}`,
    classes: 'border-retro-amber bg-retro-amber-dim text-retro-amber',
    valClass: 'text-retro-amber glow-amber',
  },
  {
    label: 'Tokens ~',
    value: props.stats.tokens_total != null
      ? props.stats.tokens_total >= 1_000_000
        ? (props.stats.tokens_total / 1_000_000).toFixed(1) + 'M'
        : props.stats.tokens_total >= 1_000
          ? (props.stats.tokens_total / 1_000).toFixed(1) + 'K'
          : props.stats.tokens_total
      : '---',
    sub: '// est. input tokens',
    classes: 'border-retro-green bg-retro-green-dim text-retro-green',
    valClass: 'text-retro-green glow-green',
  },
])
</script>
