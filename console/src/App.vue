<template>
  <div class="min-h-screen bg-retro-bg text-retro-green font-mono">

    <!-- Header -->
    <header class="border-b-2 border-retro-border bg-retro-panel sticky top-0 z-10 panel-glow">
      <div class="max-w-7xl mx-auto px-6 py-2">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-4">
            <img src="/kiteguard-logo.png" alt="KiteGuard" class="h-20 w-auto" />
            <div class="text-xs text-retro-green tracking-widest leading-relaxed opacity-60">
              <div>SECURITY CONSOLE</div>
              <div class="opacity-60">v{{ version }} :: localhost</div>
            </div>
          </div>
          <div class="flex items-center gap-5 text-xs tracking-widest">
            <div class="flex items-center gap-2" :class="error ? 'text-retro-red' : 'text-retro-green'">
              <span class="blink">█</span>
              <span>{{ error ? 'SYS.ERR' : 'SYS.ONLINE' }}</span>
            </div>
            <span class="text-retro-border">│</span>
            <span class="text-retro-green opacity-60">{{ time }}</span>
          </div>
        </div>
      </div>
    </header>

    <!-- Main -->
    <main class="max-w-7xl mx-auto px-6 py-6 space-y-6">

      <!-- Error banner -->
      <div v-if="error"
        class="border border-retro-red bg-retro-red-dim px-5 py-3 text-retro-red text-xs flex items-center gap-3">
        <span class="blink">!!</span>
        ERR :: {{ error }}
      </div>

      <!-- Metrics -->
      <section>
        <div class="text-xs text-retro-green opacity-50 tracking-widest mb-2">┌─ SYSTEM METRICS ─────────────────────────────────────────────────</div>
        <StatsBar :stats="stats" />
      </section>

      <!-- Charts -->
      <section>
        <div class="text-xs text-retro-green opacity-50 tracking-widest mb-2">┌─ THREAT ANALYSIS ────────────────────────────────────────────────</div>
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-5">
          <ThreatChart :breakdown="stats.threat_breakdown ?? {}" />
          <Timeline    :hourly="stats.hourly ?? []" />
        </div>
      </section>

      <!-- Audit log -->
      <section>
        <div class="text-xs text-retro-green opacity-50 tracking-widest mb-2">┌─ AUDIT LOG ──────────────────────────────────────────────────────</div>
        <EventsTable />
      </section>

    </main>

    <!-- Footer -->
    <footer class="border-t border-retro-border mt-10 py-4">
      <p class="text-center text-xs text-retro-green/25 tracking-widest">
        KITEGUARD :: LOCAL AUDIT CONSOLE :: ~/.kiteguard/audit.log
      </p>
    </footer>

  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { fetchStats } from '@/api/events.js'
import StatsBar    from '@/components/StatsBar.vue'
import ThreatChart from '@/components/ThreatChart.vue'
import Timeline    from '@/components/Timeline.vue'
import EventsTable from '@/components/EventsTable.vue'

const stats   = ref({})
const error   = ref('')
const version = '0.1.0'
const time    = ref(new Date().toLocaleTimeString('en-US', { hour12: false }))
let timer = null

async function refresh() {
  try {
    stats.value = await fetchStats()
    error.value = ''
  } catch (e) {
    error.value = `Cannot reach KiteGuard server: ${e.message}`
  }
}

function tick() {
  refresh()
  time.value = new Date().toLocaleTimeString('en-US', { hour12: false })
}

onMounted(() => {
  refresh()
  timer = setInterval(tick, 5000)
})
onUnmounted(() => clearInterval(timer))
</script>
