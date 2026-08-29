import { KnowledgeBase } from "@/components/knowledge-base"
import { QAWorkspace } from "@/components/qa-workspace"
import { Layers } from "lucide-react"

export default function Home() {
  return (
    <div className="min-h-[100dvh] flex flex-col bg-background selection:bg-primary/20">
      <header className="shrink-0 border-b border-border bg-card px-6 py-4 flex items-center justify-between sticky top-0 z-10 shadow-sm">
        <div className="flex items-center gap-4">
          <div className="bg-primary/10 p-2.5 rounded-lg text-primary ring-1 ring-primary/20">
            <Layers className="h-5 w-5" strokeWidth={2.5} />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-foreground leading-none">ContextForge</h1>
            <p className="text-xs text-muted-foreground font-medium mt-1">Enterprise Document Intelligence</p>
            <p className="text-[10px] text-muted-foreground/60 mt-1 uppercase tracking-widest font-semibold">Demo mode · ephemeral state resets on API restart</p>
          </div>
        </div>
        
        <div className="hidden md:flex items-center text-[10px] font-mono font-medium text-muted-foreground bg-secondary/50 px-4 py-2 rounded-md border border-border/50 tracking-wider">
          Ingest &rarr; Chunk &rarr; Retrieve &rarr; Generate &rarr; Cite
        </div>
      </header>

      <main className="flex-1 container mx-auto max-w-7xl p-6 md:p-8">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 h-[calc(100dvh-130px)] min-h-[600px]">
          {/* Left Column: Knowledge Base management */}
          <div className="lg:col-span-5 flex flex-col h-full overflow-y-auto pr-2 pb-8 lg:pb-0">
            <KnowledgeBase />
          </div>
          
          {/* Right Column: Q&A Flow */}
          <div className="lg:col-span-7 flex flex-col h-full pb-8 lg:pb-0">
            <QAWorkspace />
          </div>
        </div>
      </main>
    </div>
  )
}
