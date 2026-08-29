import { useState, useRef, useEffect } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { CornerDownLeft, Loader2, BookOpen, Quote, ShieldCheck, ShieldAlert, Cpu } from "lucide-react"

import { useAskKnowledgeBase } from "@workspace/api-client-react"
import type { Answer, Source } from "@workspace/api-client-react"

import { Button } from "@/components/ui/button"
import { Textarea } from "@/components/ui/textarea"
import { Card, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"

const questionSchema = z.object({
  question: z.string().min(3, "Question must be at least 3 characters").max(1000, "Question is too long"),
})

export function QAWorkspace() {
  const [history, setHistory] = useState<Array<{ type: "question" | "answer" | "error", content: string, answerData?: Answer }>>([])
  
  const askMutation = useAskKnowledgeBase()
  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [history, askMutation.isPending])

  const form = useForm<z.infer<typeof questionSchema>>({
    resolver: zodResolver(questionSchema),
    defaultValues: {
      question: "",
    },
  })

  function onSubmit(values: z.infer<typeof questionSchema>) {
    const question = values.question
    form.reset()
    
    setHistory(prev => [...prev, { type: "question", content: question }])
    
    askMutation.mutate({ data: { question } }, {
      onSuccess: (answer) => {
        setHistory(prev => [...prev, { type: "answer", content: answer.answer, answerData: answer }])
      },
      onError: (err: any) => {
        let errorMessage = "Failed to generate an answer. Please try again."
        if (err?.data?.message) {
          errorMessage = err.data.message
        } else if (err?.data?.error) {
          errorMessage = err.data.error
        } else if (err?.message) {
          errorMessage = err.message
        } else if (typeof err === 'string') {
          errorMessage = err
        }
        setHistory(prev => [...prev, { type: "error", content: errorMessage }])
      }
    })
  }

  return (
    <Card className="flex flex-col h-full border-border shadow-sm overflow-hidden bg-background" data-testid="qa-workspace">
      <CardHeader className="border-b border-border bg-card/50 pb-4 shrink-0">
        <div className="flex items-center gap-2">
          <Cpu className="h-5 w-5 text-primary" />
          <CardTitle className="text-base font-semibold">Intelligence Engine</CardTitle>
        </div>
        <CardDescription className="text-xs">
          Query the ingested corpus. Synthesis is strictly constrained to retrieved context blocks.
        </CardDescription>
      </CardHeader>
      
      <div 
        ref={scrollRef}
        className="flex-1 overflow-y-auto p-4 space-y-6 bg-secondary/10"
      >
        {history.length === 0 && (
          <div className="h-full flex flex-col items-center justify-center text-center px-8 text-muted-foreground/50 space-y-4">
            <div className="bg-background p-4 rounded-xl border border-border shadow-sm">
              <BookOpen className="h-8 w-8 text-muted-foreground" />
            </div>
            <div className="space-y-1">
              <p className="font-semibold text-foreground">Awaiting Query</p>
              <p className="text-xs text-muted-foreground max-w-[280px]">
                The engine will retrieve relevant chunks and construct a grounded response.
              </p>
            </div>
          </div>
        )}

        {history.map((entry, i) => (
          <div key={i} className="space-y-3" data-testid={`chat-entry-${i}`}>
            {entry.type === "question" ? (
              <div className="flex justify-end">
                <div className="bg-foreground text-background px-4 py-3 rounded-xl rounded-tr-sm max-w-[85%] shadow-sm text-sm font-medium">
                  {entry.content}
                </div>
              </div>
            ) : entry.type === "error" ? (
              <div className="flex justify-start">
                <div className="bg-destructive/10 border border-destructive/20 text-destructive px-4 py-3 rounded-xl rounded-tl-sm max-w-[85%] text-sm font-medium">
                  {entry.content}
                </div>
              </div>
            ) : (
              <div className="flex justify-start">
                <div className="bg-card border border-border shadow-sm rounded-xl rounded-tl-sm max-w-[95%] w-full overflow-hidden">
                  <div className="px-5 py-4 space-y-4">
                    <div className="prose prose-sm dark:prose-invert max-w-none text-foreground leading-relaxed">
                      {entry.content}
                    </div>
                  </div>
                  
                  {entry.answerData && entry.answerData.sources.length > 0 && (
                    <div className="bg-secondary/30 border-t border-border px-5 py-4 space-y-3">
                      <div className="flex items-center gap-3">
                        {entry.answerData.grounded ? (
                          <Badge variant="outline" className="text-[10px] font-mono py-0 h-5 border-emerald-500/30 text-emerald-600 bg-emerald-500/10 flex items-center gap-1">
                            <ShieldCheck className="h-3 w-3" />
                            GROUNDED
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="text-[10px] font-mono py-0 h-5 border-amber-500/30 text-amber-600 bg-amber-500/10 flex items-center gap-1">
                            <ShieldAlert className="h-3 w-3" />
                            UNCERTAIN
                          </Badge>
                        )}
                        <span className="text-[10px] text-muted-foreground uppercase tracking-widest font-semibold">
                          {entry.answerData.retrievedChunks} chunks retrieved
                        </span>
                      </div>
                      
                      <div className="grid gap-2">
                        {entry.answerData.sources.map((source, idx) => (
                          <SourceCard key={`${source.documentId}-${idx}`} source={source} idx={idx} />
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        ))}

        {askMutation.isPending && (
          <div className="flex justify-start" data-testid="chat-entry-loading">
            <div className="bg-card border border-border rounded-xl rounded-tl-sm w-full max-w-[80%] shadow-sm">
              <div className="px-5 py-4 space-y-4">
                <div className="flex items-center gap-2 text-primary text-xs font-semibold uppercase tracking-widest">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  Synthesizing...
                </div>
                <div className="space-y-2">
                  <Skeleton className="h-4 w-full" />
                  <Skeleton className="h-4 w-[90%]" />
                  <Skeleton className="h-4 w-[60%]" />
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="p-4 border-t border-border bg-card shrink-0">
        <form 
          onSubmit={form.handleSubmit(onSubmit)} 
          className="relative rounded-lg border border-input bg-background focus-within:ring-1 focus-within:ring-primary focus-within:border-primary transition-shadow shadow-sm"
        >
          <Textarea 
            placeholder="Query the corpus..."
            className="min-h-[56px] resize-none border-0 focus-visible:ring-0 focus-visible:ring-offset-0 bg-transparent py-3 px-4 pr-12 text-sm"
            data-testid="input-question"
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault()
                form.handleSubmit(onSubmit)()
              }
            }}
            {...form.register("question")}
          />
          <div className="absolute right-2 bottom-2">
            <Button 
              type="submit" 
              size="icon" 
              disabled={askMutation.isPending || !form.watch("question")?.trim()}
              className="h-8 w-8 rounded-md"
              data-testid="button-ask"
            >
              <CornerDownLeft className="h-4 w-4" />
              <span className="sr-only">Submit Query</span>
            </Button>
          </div>
        </form>
        <div className="mt-2 text-center">
          <span className="text-[10px] text-muted-foreground uppercase tracking-widest font-semibold">
            Return to execute · Shift+Return for newline
          </span>
        </div>
      </div>
    </Card>
  )
}

function SourceCard({ source, idx }: { source: Source, idx: number }) {
  return (
    <div className="rounded-md bg-background border border-border/50 p-3 space-y-2" data-testid={`card-source-${idx}`}>
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 overflow-hidden">
          <Quote className="h-3 w-3 text-muted-foreground shrink-0" />
          <span className="font-semibold text-xs truncate text-foreground">{source.documentName}</span>
          <span className="text-[10px] text-muted-foreground shrink-0 font-mono border-l border-border pl-2">Chunk {source.chunkIndex}</span>
        </div>
        <Badge variant="secondary" className="text-[9px] font-mono py-0 h-4 rounded-sm bg-muted text-muted-foreground">
          Rel: {source.score.toFixed(2)}
        </Badge>
      </div>
      <p className="text-xs text-muted-foreground font-mono leading-relaxed line-clamp-2 pl-5">
        {source.excerpt}
      </p>
    </div>
  )
}
