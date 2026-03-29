<template>
  <div class="border border-retro-border bg-retro-panel p-5 panel-glow">
    <div class="flex items-center gap-2 mb-5">
      <span class="text-retro-amber">▶</span>
      <h2 class="text-xs tracking-widest uppercase text-retro-green opacity-70">[ EVENTS_TIMELINE ]</h2>
    </div>
    <div v-if="hasData" style="height:240px">
      <Bar :data="chartData" :options="options" />
    </div>
    <p v-else class="text-center text-retro-green opacity-40 py-10 text-xs tracking-widest">
      :: NO DATA LOADED ::
    </p>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { Bar } from 'vue-chartjs'
import { Chart as ChartJS, BarElement, CategoryScale, LinearScale, Tooltip, Legend } from 'chart.js'

ChartJS.register(BarElement, CategoryScale, LinearScale, Tooltip, Legend)

const props = defineProps({
  hourly: { type: Array, default: () => [] }
})

const hasData = computed(() => props.hourly.length > 0)

const chartData = computed(() => ({
  labels: props.hourly.map(b => b.hour),
  datasets: [{
    label: 'Events',
    data:  props.hourly.map(b => b.count),
    backgroundColor: '#0a6e0a22',
    borderColor: '#0a6e0a',
    borderWidth: 1,
    borderRadius: 0,
  }],
}))

const options = {
  responsive: true,
  maintainAspectRatio: false,
  scales: {
    x: {
      ticks: { color: '#666660', font: { size: 10, family: '"Share Tech Mono", monospace' } },
      grid:  { color: '#e8e8e0' },
      border: { color: '#d4d4c8' },
    },
    y: {
      ticks: { color: '#666660', font: { size: 10, family: '"Share Tech Mono", monospace' }, stepSize: 1 },
      grid:  { color: '#e8e8e0' },
      border: { color: '#d4d4c8' },
      beginAtZero: true,
    },
  },
  plugins: {
    legend: { display: false },
    tooltip: {
      backgroundColor: '#ffffff',
      borderColor: '#d4d4c8',
      borderWidth: 1,
      titleColor: '#1a1a1a',
      bodyColor: '#444440',
      callbacks: { label: ctx => ` ${ctx.parsed.y} events` },
    },
  },
}
</script>
