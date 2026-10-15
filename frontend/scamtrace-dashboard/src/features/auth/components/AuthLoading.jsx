import { Loader2 } from 'lucide-react'

export default function AuthLoading() {
  return (
    <main className="flex-1 flex items-center justify-center py-24 bg-slate-950 text-slate-400">
      <Loader2 className="w-5 h-5 mr-2 animate-spin" /> Checking your session…
    </main>
  )
}
