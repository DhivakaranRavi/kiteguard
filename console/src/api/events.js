const BASE = import.meta.env.DEV ? 'http://localhost:7070' : ''

export async function fetchStats() {
  const res = await fetch(`${BASE}/api/stats`)
  if (!res.ok) throw new Error('Failed to fetch stats')
  return res.json()
}

export async function fetchEvents(params = {}) {
  const query = new URLSearchParams()
  if (params.page)    query.set('page',    params.page)
  if (params.limit)   query.set('limit',   params.limit)
  if (params.verdict) query.set('verdict', params.verdict)
  if (params.hook)    query.set('hook',    params.hook)
  if (params.client)  query.set('client',  params.client)
  const res = await fetch(`${BASE}/api/events?${query}`)
  if (!res.ok) throw new Error('Failed to fetch events')
  return res.json()
}
