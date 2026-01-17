export const formatBantime = (s: string) => {
  const n = parseInt(s, 10)
  if (n === -1) return 'Permanent'
  if (n >= 86400) return `${Math.floor(n / 86400)} days`
  if (n >= 3600) return `${Math.floor(n / 3600)} hours`
  if (n >= 60) return `${Math.floor(n / 60)} min`
  return `${n} sec`
}