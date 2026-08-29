import { useState, useRef, useEffect } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { CornerDownLeft, Loader2, Sparkles, BookOpen, Quote } from "lucide-react"

import { useAskKnowledgeBase } from "@workspace/api-client-react"
import type { Answer, Source } from "@workspace/api-client-react"

import { Button } from "@/components/ui/button"
import { Textarea } from "@/components/ui/textarea"
import { Card, CardContent, CardHeader, CardTitle, CardDescription, CardFooter } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "./ui/skeleton"

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
    <Card className="flex flex-col h-full border-muted-foreground/20 shadow-md overflow-hidden bg-card" data-testid="qa-workspace">
      <CardHeader className="border-b bg-muted/30 pb-4 shrink-0">
        <div className="flex items-center gap-2">
          <Sparkles className="h-5 w-5 text-primary" />
          <CardTitle>Grounded Q&A</CardTitle>
        </div>
        <CardDescription>
          Ask questions against the indexed knowledge base. The LLM will only answer using retrieved chunks.
        </CardDescription>
      </CardHeader>
      
      <div 
        ref={scrollRef}
        className="flex-1 overflow-y-auto p-4 space-y-6 bg-secondary/10"
      >
        {history.length === 0 && (
          <div className="h-full flex flex-col items-center justify-center text-center px-8 text-muted-foreground/60 space-y-4">
            <BookOpen className="h-12 w-12" />
            <div className="space-y-1">
              <p className="font-medium text-foreground">Awaiting your question</p>
              <p className="text-sm text-muted-foreground">
                Indexed documents will be searched and used to form a grounded response.
              </p>
            </div>
          </div>
        )}

        {history.map((entry, i) => (
          <div key={i} className="space-y-3" data-testid={`chat-entry-${i}`}>
            {entry.type === "question" ? (
              <div className="flex justify-end">
                <div className="bg-primary text-primary-foreground px-4 py-2.5 rounded-2xl rounded-tr-sm max-w-[85%] shadow-sm text-sm font-medium">
                  {entry.content}
                </div>
              </div>
            ) : entry.type === "error" ? (
              <div className="flex justify-start">
                <div className="bg-destructive/10 border border-destructive/20 text-destructive px-4 py-2.5 rounded-2xl rounded-tl-sm max-w-[85%] text-sm">
                  {entry.content}
                </div>
              </div>
            ) : (
              <div className="flex justify-start">
                <div className="bg-card border border-border shadow-sm px-5 py-4 rounded-2xl rounded-tl-sm max-w-[90%] space-y-4">
                  <div className="prose prose-sm dark:prose-invert max-w-none">
                    {entry.content}
                  </div>
                  
                  {entry.answerData && entry.answerData.sources.length > 0 && (
                    <div className="mt-4 pt-4 border-t space-y-3">
                      <div className="flex items-center gap-2">
                        <Badge variant={entry.answerData.grounded ? "default" : "secondary"} className="text-[10px]">
                          {entry.answerData.grounded ? "Grounded" : "Uncertain Grounding"}
                        </Badge>
                        <span className="text-xs text-muted-foreground font-mono">
                          Retrieved {entry.answerData.retrievedChunks} chunks
                        </span>
                      </div>
                      
                      <div className="space-y-2">
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
            <div className="bg-card border border-border px-5 py-4 rounded-2xl rounded-tl-sm w-full max-w-[70%] space-y-3">
              <div className="flex items-center gap-2 text-primary text-sm font-medium">
                <Loader2 className="h-4 w-4 animate-spin" />
                Synthesizing answer...
              </div>
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-4 w-[90%]" />
              <Skeleton className="h-4 w-[60%]" />
            </div>
          </div>
        )}
      </div>

      <div className="p-4 border-t bg-card shrink-0">
        <form 
          onSubmit={form.handleSubmit(onSubmit)} 
          className="relative rounded-xl border border-input bg-background focus-within:ring-2 focus-within:ring-ring focus-within:ring-offset-2 focus-within:ring-offset-background transition-shadow shadow-sm"
        >
          <Textarea 
            placeholder="Ask about your documents..."
            className="min-h-[60px] resize-none border-0 focus-visible:ring-0 focus-visible:ring-offset-0 bg-transparent py-3 px-4 pr-14 text-sm"
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
              className="h-8 w-8 rounded-lg"
              data-testid="button-ask"
            >
              <CornerDownLeft className="h-4 w-4" />
              <span className="sr-only">Ask</span>
            </Button>
          </div>
        </form>
        <div className="mt-2 text-center">
          <span className="text-[10px] text-muted-foreground uppercase tracking-widest font-semibold">
            Press Enter to ask, Shift+Enter for new line
          </span>
        </div>
      </div>
    </Card>
  )
}

function SourceCard({ source, idx }: { source: Source, idx: number }) {
  return (
    <div className="rounded-lg bg-muted/50 border border-border/50 p-3 space-y-2 text-sm" data-testid={`card-source-${idx}`}>
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-1.5 overflow-hidden">
          <Quote className="h-3 w-3 text-muted-foreground shrink-0" />
          <span className="font-semibold text-xs truncate text-foreground">{source.documentName}</span>
          <span className="text-xs text-muted-foreground shrink-0 font-mono">Chunk {source.chunkIndex}</span>
        </div>
        <Badge variant="outline" className="text-[9px] font-mono py-0 h-4 bg-background">
          Score: {source.score.toFixed(2)}
        </Badge>
      </div>
      <p className="text-xs text-muted-foreground font-mono leading-relaxed line-clamp-3 bg-background/50 rounded p-2 border border-border/40">
        {source.excerpt}
      </p>
    </div>
  )
}
