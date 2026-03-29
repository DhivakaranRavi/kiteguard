<template>
  <div class="border border-retro-border bg-retro-panel p-5 panel-glow">
    <div class="flex items-center gap-2 mb-5">
      <span class="text-retro-amber">▶</span>
      <h2 class="text-xs tracking-widest uppercase text-retro-green opacity-70">[ THREAT_BREAKDOWN ]</h2>
    </div>
    <div v-if="hasData" class="flex items-center justify-center" style="max-height:260px">
      <Doughnut :data="chartData" :options="options" />
    </div>
    <p v-else class="text-center text-retro-green opacity-40 py-10 text-xs tracking-widest">
      :: NO DATA LOADED ::
    </p>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { Doughnut } from 'vue-chartjs'
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js'

ChartJS.register(ArcElement, Tooltip, Legend)

const props = defineProps({
  breakdown: { type: Object, default: () => ({}) }
})

const PALETTE = ['#7a4f00', '#8a0f0f', '#0a6e0a', '#005f7a', '#7a005f', '#1a4f8a', '#8a5a00']

const hasData = computed(() => Object.keys(props.breakdown).length > 0)

const chartData = computed(() => {
  const labels = Object.keys(props.breakdown)
  const data   = Object.values(props.breakdown)
  return {
    labels,
    datasets: [{
      data,
      backgroundColor: labels.map((_, i) => PALETTE[i % PALETTE.length] + '22'),
      borderColor:     labels.map((_, i) => PALETTE[i % PALETTE.length]),
      borderWidth: 2,
      hoverOffset: 8,
    }],
  }
})

const options = {
  cutout: '65%',
  responsive: true,
  maintainAspectRatio: true,
  plugins: {
    legend: {
      position: 'bottom',
      labels: {
        color: '#1a1a1a',
        padding: 16,
        font: { size: 11, family: '"Share Tech Mono", monospace' },
        boxWidth: 10,
        boxHeight: 10,
      },
    },
    tooltip: {
      backgroundColor: '#ffffff',
      borderColor: '#d4d4c8',
      borderWidth: 1,
      titleColor: '#1a1a1a',
      bodyColor: '#444440',
      callbacks: { label: ctx => ` ${ctx.parsed} events` },
    },
  },
}
</script>
