import { useState, useRef } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { useQueryClient } from "@tanstack/react-query"
import { Plus, FileText, Loader2, File, Activity, Upload } from "lucide-react"

import {
  useListDocuments,
  useCreateDocument,
  useGetKnowledgeSummary,
  getListDocumentsQueryKey,
  getGetKnowledgeSummaryQueryKey,
} from "@workspace/api-client-react"

import { Button } from "@/components/ui/button"
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { Badge } from "@/components/ui/badge"

const createDocSchema = z.object({
  name: z.string().min(1, "Name is required").max(120, "Name is too long"),
  content: z.string().min(20, "Content must be at least 20 characters").max(100000, "Content is too long"),
})

export function KnowledgeBase() {
  return (
    <div className="flex flex-col gap-6 h-full w-full">
      <KnowledgeSummary />
      <AddDocumentForm />
      <DocumentList />
    </div>
  )
}

function KnowledgeSummary() {
  const { data: summary, isLoading, isError } = useGetKnowledgeSummary({
    query: { queryKey: getGetKnowledgeSummaryQueryKey() }
  })

  if (isLoading) {
    return (
      <Card data-testid="card-knowledge-summary-loading">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">Knowledge Base Status</CardTitle>
        </CardHeader>
        <CardContent className="flex gap-4">
          <Skeleton className="h-10 w-20" />
          <Skeleton className="h-10 w-20" />
        </CardContent>
      </Card>
    )
  }

  if (isError || !summary) {
    return null
  }

  return (
    <Card className="bg-primary/5 border-primary/20" data-testid="card-knowledge-summary">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-primary flex items-center gap-2">
          <Activity className="h-4 w-4" />
          Knowledge Base Indexed
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex items-end gap-6">
          <div className="space-y-1">
            <p className="text-2xl font-bold font-mono text-foreground" data-testid="text-summary-docs">{summary.documentCount}</p>
            <p className="text-xs text-muted-foreground uppercase tracking-wider font-semibold">Documents</p>
          </div>
          <div className="space-y-1">
            <p className="text-2xl font-bold font-mono text-foreground" data-testid="text-summary-chunks">{summary.chunkCount}</p>
            <p className="text-xs text-muted-foreground uppercase tracking-wider font-semibold">Chunks</p>
          </div>
          <div className="space-y-1">
            <p className="text-2xl font-bold font-mono text-foreground" data-testid="text-summary-chars">
              {(summary.characterCount / 1000).toFixed(1)}k
            </p>
            <p className="text-xs text-muted-foreground uppercase tracking-wider font-semibold">Characters</p>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

function AddDocumentForm() {
  const queryClient = useQueryClient()
  const createDocument = useCreateDocument()
  const fileInputRef = useRef<HTMLInputElement>(null)
  
  const form = useForm<z.infer<typeof createDocSchema>>({
    resolver: zodResolver(createDocSchema),
    defaultValues: {
      name: "",
      content: "",
    },
  })

  function handleFileUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return

    const reader = new FileReader()
    reader.onload = (event) => {
      const text = event.target?.result as string
      form.setValue("name", file.name, { shouldValidate: true })
      form.setValue("content", text, { shouldValidate: true })
    }
    reader.readAsText(file)
    
    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
  }

  function onSubmit(values: z.infer<typeof createDocSchema>) {
    createDocument.mutate({ data: values }, {
      onSuccess: () => {
        form.reset()
        queryClient.invalidateQueries({ queryKey: getListDocumentsQueryKey() })
        queryClient.invalidateQueries({ queryKey: getGetKnowledgeSummaryQueryKey() })
      }
    })
  }

  return (
    <Card data-testid="card-add-document">
      <CardHeader className="flex flex-row items-start justify-between space-y-0 pb-4">
        <div className="space-y-1.5">
          <CardTitle className="text-base">Add Context</CardTitle>
          <CardDescription>Paste raw text or markdown to ground the LLM.</CardDescription>
        </div>
        <div>
          <Button 
            type="button" 
            variant="outline" 
            size="sm" 
            onClick={() => fileInputRef.current?.click()}
            data-testid="button-upload-file"
          >
            <Upload className="h-4 w-4 mr-2" />
            Upload .txt/.md
          </Button>
          <input 
            type="file" 
            accept=".txt,.md,text/plain,text/markdown" 
            className="hidden" 
            ref={fileInputRef} 
            onChange={handleFileUpload} 
            data-testid="input-file-upload"
          />
        </div>
      </CardHeader>
      <CardContent>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Document Name</FormLabel>
                  <FormControl>
                    <Input placeholder="e.g. Architecture RFC 1.0" data-testid="input-doc-name" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="content"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Content</FormLabel>
                  <FormControl>
                    <Textarea 
                      placeholder="Paste document content here..." 
                      className="min-h-[120px] font-mono text-xs resize-y"
                      data-testid="input-doc-content"
                      {...field} 
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <div className="flex justify-end">
              <Button type="submit" disabled={createDocument.isPending} data-testid="button-submit-doc">
                {createDocument.isPending ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : (
                  <Plus className="mr-2 h-4 w-4" />
                )}
                Index Document
              </Button>
            </div>
          </form>
        </Form>
      </CardContent>
    </Card>
  )
}

function DocumentList() {
  const { data: documents, isLoading, isError } = useListDocuments({
    query: { queryKey: getListDocumentsQueryKey() }
  })

  if (isLoading) {
    return (
      <div className="space-y-3" data-testid="list-docs-loading">
        <Skeleton className="h-16 w-full" />
        <Skeleton className="h-16 w-full" />
        <Skeleton className="h-16 w-full" />
      </div>
    )
  }

  if (isError) {
    return (
      <div className="p-4 rounded-lg bg-destructive/10 text-destructive text-sm" data-testid="text-docs-error">
        Failed to load documents.
      </div>
    )
  }

  if (!documents || documents.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 px-4 text-center border-2 border-dashed rounded-xl" data-testid="empty-docs">
        <FileText className="h-10 w-10 text-muted-foreground mb-3" />
        <p className="text-sm font-medium text-foreground">No documents indexed</p>
        <p className="text-sm text-muted-foreground mt-1 max-w-[200px]">
          Add text context above to start grounding the LLM.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-3" data-testid="list-docs">
      <h3 className="text-sm font-medium text-foreground px-1">Indexed Content</h3>
      {documents.map(doc => (
        <Card key={doc.id} className="bg-card shadow-sm hover:border-primary/30 transition-colors" data-testid={`card-doc-${doc.id}`}>
          <div className="p-4 flex items-center justify-between gap-4">
            <div className="flex items-center gap-3 overflow-hidden">
              <div className="h-8 w-8 rounded-md bg-primary/10 flex items-center justify-center shrink-0">
                <File className="h-4 w-4 text-primary" />
              </div>
              <div className="overflow-hidden">
                <p className="text-sm font-medium truncate" title={doc.name}>{doc.name}</p>
                <p className="text-xs text-muted-foreground mt-0.5 truncate font-mono">
                  {new Date(doc.createdAt).toLocaleDateString()}
                </p>
              </div>
            </div>
            <Badge variant="secondary" className="shrink-0 font-mono text-[10px]">
              {doc.chunkCount} chunks
            </Badge>
          </div>
        </Card>
      ))}
    </div>
  )
}
