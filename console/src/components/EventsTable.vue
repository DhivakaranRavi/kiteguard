<template>
  <div class="border border-retro-border bg-retro-panel p-5 panel-glow">

    <!-- Toolbar -->
    <div class="flex flex-wrap items-center gap-3 mb-5">
      <h2 class="text-xs tracking-widest uppercase text-retro-green opacity-70 flex-1">[ AUDIT_LOG_VIEWER ]</h2>

      <select v-model="filterVerdict"
        class="bg-white border border-retro-border text-gray-700 text-xs px-3 py-1.5 tracking-wider outline-none focus:border-retro-green cursor-pointer">
        <option value="">-- ALL VERDICTS --</option>
        <option value="Block">BLOCK</option>
        <option value="Allow">ALLOW</option>
      </select>

      <select v-model="filterHook"
        class="bg-white border border-retro-border text-gray-700 text-xs px-3 py-1.5 tracking-wider outline-none focus:border-retro-green cursor-pointer">
        <option value="">-- ALL HOOKS --</option>
        <option value="UserPromptSubmit">UserPromptSubmit</option>
        <option value="PreToolUse">PreToolUse</option>
        <option value="PostToolUse">PostToolUse</option>
        <option value="Stop">Stop</option>
      </select>

      <span class="text-xs text-gray-400 tracking-widest">{{ (page - 1) * 100 + 1 }}–{{ Math.min(page * 100, total) }} of {{ total }}</span>
    </div>

    <!-- Table -->
    <div class="overflow-x-auto">
      <table class="w-full text-xs">
        <thead>
          <tr class="text-retro-green/40 tracking-widest uppercase border-b border-retro-border">
            <th class="text-left pb-3 pr-6 font-normal whitespace-nowrap">TIMESTAMP</th>
            <th class="text-left pb-3 pr-6 font-normal">HOOK</th>
            <th class="text-left pb-3 pr-6 font-normal">VERDICT</th>
            <th class="text-left pb-3 pr-6 font-normal">REPO</th>
            <th class="text-left pb-3 font-normal">USER</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="loading">
            <td colspan="5" class="py-10 text-center text-gray-400 tracking-widest">
              <span class="blink">█</span> LOADING ...
            </td>
          </tr>
          <tr v-else-if="events.length === 0">
            <td colspan="5" class="py-10 text-center text-gray-400 tracking-widest">
              :: NO RECORDS FOUND ::
            </td>
          </tr>
          <tr
            v-for="(ev, i) in events"
            :key="i"
            class="border-b border-retro-border/30 transition-colors cursor-pointer"
            :class="ev.verdict === 'Block' ? 'hover:bg-retro-red-dim/40' : 'hover:bg-retro-green-dim'"
            @click="selectedEvent = ev"
          >
            <td class="py-2.5 pr-6 text-gray-500 whitespace-nowrap">{{ formatTs(ev.ts) }}</td>
            <td class="py-2.5 pr-6 text-retro-cyan opacity-80 tracking-wide">{{ ev.hook || '—' }}</td>
            <td class="py-2.5 pr-6">
              <span
                class="inline-flex items-center gap-1.5 tracking-widest"
                :class="ev.verdict === 'Block' ? 'text-retro-red glow-red' : 'text-retro-green glow-green'"
              >
                <span>{{ ev.verdict === 'Block' ? '✕' : '✓' }}</span>
                {{ ev.verdict?.toUpperCase() }}
              </span>
            </td>
            <td class="py-2.5 pr-6 text-gray-500 truncate max-w-[140px]">{{ ev.repo || '—' }}</td>
            <td class="py-2.5 text-gray-500">{{ ev.user || '—' }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Pagination -->
    <div class="flex items-center justify-between mt-5 pt-4 border-t border-retro-border/30">
      <button
        :disabled="page <= 1"
        @click="page--"
        class="px-4 py-1.5 text-xs border border-retro-green/30 text-retro-green/60 tracking-widest
               disabled:opacity-20 disabled:cursor-not-allowed hover:border-retro-green hover:text-retro-green transition-colors">
        [← PREV]
      </button>
      <span class="text-xs text-gray-400 tracking-widest">
        PAGE {{ page }} / {{ totalPages }} &nbsp;·&nbsp; {{ total }} RECORDS
      </span>
      <button
        :disabled="page >= totalPages"
        @click="page++"
        class="px-4 py-1.5 text-xs border border-retro-green/30 text-retro-green/60 tracking-widest
               disabled:opacity-20 disabled:cursor-not-allowed hover:border-retro-green hover:text-retro-green transition-colors">
        [NEXT →]
      </button>
    </div>

  </div>

  <!-- ── Event Detail Modal ───────────────────────────────────────── -->
  <Teleport to="body">
    <Transition name="modal">
      <div
        v-if="selectedEvent"
        class="fixed inset-0 z-50 flex items-center justify-center p-4"
        style="background:rgba(0,0,0,0.82)"
        @click.self="selectedEvent = null"
      >
        <div
          class="relative w-full max-w-2xl border panel-glow text-xs font-mono"
          :class="selectedEvent.verdict === 'Block'
            ? 'border-retro-red bg-retro-panel'
            : 'border-retro-green bg-retro-panel'"
        >
          <!-- Title bar -->
          <div
            class="flex items-center justify-between px-4 py-2 border-b"
            :class="selectedEvent.verdict === 'Block' ? 'border-retro-red/40 bg-retro-red/10' : 'border-retro-green/40 bg-retro-green/10'"
          >
            <span
              class="tracking-widest uppercase"
              :class="selectedEvent.verdict === 'Block' ? 'text-retro-red glow-red' : 'text-retro-green glow-green'"
            >
              {{ selectedEvent.verdict === 'Block' ? '✕ BLOCKED' : '✓ ALLOWED' }} — EVENT DETAIL
            </span>
            <button
              @click="selectedEvent = null"
              class="text-gray-400 hover:text-white transition-colors tracking-widest px-2 py-0.5 border border-transparent hover:border-gray-600"
            >[✕ CLOSE]</button>
          </div>

          <!-- Body -->
          <div class="p-5 space-y-3">
            <div class="grid grid-cols-[140px_1fr] gap-y-3 gap-x-4">
              <span class="text-retro-green/50 tracking-widest uppercase">TIMESTAMP</span>
              <span class="text-gray-300">{{ formatTs(selectedEvent.ts) }}</span>

              <span class="text-retro-green/50 tracking-widest uppercase">HOOK</span>
              <span class="text-retro-cyan">{{ selectedEvent.hook || '—' }}</span>

              <span class="text-retro-green/50 tracking-widest uppercase">VERDICT</span>
              <span :class="selectedEvent.verdict === 'Block' ? 'text-retro-red glow-red' : 'text-retro-green glow-green'" class="tracking-widest">
                {{ selectedEvent.verdict === 'Block' ? '✕' : '✓' }} {{ selectedEvent.verdict?.toUpperCase() }}
              </span>

              <span class="text-retro-green/50 tracking-widest uppercase">RULE</span>
              <span class="text-retro-amber">{{ selectedEvent.rule || '—' }}</span>

              <template v-if="selectedEvent.reason">
                <span class="text-retro-green/50 tracking-widest uppercase self-start pt-0.5">REASON</span>
                <span
                  class="text-gray-200 leading-relaxed break-words"
                  :class="selectedEvent.verdict === 'Block' ? 'text-retro-red/90' : 'text-gray-200'"
                >{{ selectedEvent.reason }}</span>
              </template>

              <span class="text-retro-green/50 tracking-widest uppercase">REPO</span>
              <span class="text-gray-300">{{ selectedEvent.repo || '—' }}</span>

              <span class="text-retro-green/50 tracking-widest uppercase">USER</span>
              <span class="text-gray-300">{{ selectedEvent.user || '—' }}</span>

              <span class="text-retro-green/50 tracking-widest uppercase">HOST</span>
              <span class="text-gray-300">{{ selectedEvent.host || '—' }}</span>

              <template v-if="selectedEvent.input_hash">
                <span class="text-retro-green/50 tracking-widest uppercase">INPUT HASH</span>
                <span class="text-gray-500 break-all">{{ selectedEvent.input_hash }}</span>
              </template>
            </div>
          </div>

          <!-- Footer -->
          <div class="px-5 py-3 border-t border-retro-border/40 text-gray-600 tracking-widest text-[10px]">
            CLICK OUTSIDE OR [✕ CLOSE] TO DISMISS
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>

</template>

<script setup>
import { ref, watch, onMounted } from 'vue'
import { fetchEvents } from '@/api/events.js'

const LIMIT = 100
const events        = ref([])
const total         = ref(0)
const page          = ref(1)
const totalPages    = ref(1)
const loading       = ref(false)
const filterVerdict = ref('')
const filterHook    = ref('')
const selectedEvent = ref(null)

async function load() {
  loading.value = true
  try {
    const data = await fetchEvents({
      page:    page.value,
      limit:   LIMIT,
      verdict: filterVerdict.value || undefined,
      hook:    filterHook.value    || undefined,
    })
    events.value     = data.events
    total.value      = data.total
    totalPages.value = Math.max(1, Math.ceil(data.total / LIMIT))
  } catch {
    events.value = []
  } finally {
    loading.value = false
  }
}

function formatTs(ts) {
  if (!ts) return '—'
  try {
    return new Date(ts).toLocaleString('en-US', {
      year: '2-digit', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: false,
    })
  } catch { return ts }
}

watch([filterVerdict, filterHook], () => { page.value = 1; load() })
watch(page, load)
onMounted(load)
</script>

<style scoped>
.modal-enter-active,
.modal-leave-active {
  transition: opacity 0.15s ease;
}
.modal-enter-from,
.modal-leave-to {
  opacity: 0;
}
.modal-enter-active > div,
.modal-leave-active > div {
  transition: transform 0.15s ease;
}
.modal-enter-from > div {
  transform: scale(0.95);
}
.modal-leave-to > div {
  transform: scale(0.95);
}
</style>
