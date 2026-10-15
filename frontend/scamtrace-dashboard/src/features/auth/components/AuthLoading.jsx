import { Loader2 } from 'lucide-react'

export default function AuthLoading({ light = false }) {
  const theme = light ? 'st-blue-backdrop min-h-screen text-st-muted' : 'bg-slate-950 text-slate-400'
  return (
    <main className={`flex-1 flex items-center justify-center py-24 ${theme}`}>
      <Loader2 className="w-5 h-5 mr-2 animate-spin" /> Checking your session…
    </main>
  )
}
