import { useState, useRef, useCallback } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { useQueryClient } from "@tanstack/react-query"
import { Plus, FileText, Loader2, File, Activity, UploadCloud, Type, HardDrive, AlertCircle, FileJson, FileSpreadsheet, FileCode } from "lucide-react"

import {
  useListDocuments,
  useCreateDocument,
  useUploadDocument,
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

const MAX_FILE_SIZE = 10 * 1024 * 1024 // 10 MB

export function KnowledgeBase() {
  return (
    <div className="flex flex-col gap-6 h-full w-full">
      <KnowledgeSummary />
      <AddDocumentControls />
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
      <Card data-testid="card-knowledge-summary-loading" className="border-border shadow-sm">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">Corpus Status</CardTitle>
        </CardHeader>
        <CardContent className="flex gap-6">
          <Skeleton className="h-12 w-24" />
          <Skeleton className="h-12 w-24" />
          <Skeleton className="h-12 w-24" />
        </CardContent>
      </Card>
    )
  }

  if (isError || !summary) {
    return null
  }

  return (
    <Card className="bg-primary/5 border-primary/20 shadow-sm" data-testid="card-knowledge-summary">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-semibold text-primary flex items-center gap-2">
          <Activity className="h-4 w-4" />
          Corpus Overview
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex items-end gap-8">
          <div className="space-y-1">
            <p className="text-3xl font-bold font-mono text-foreground tracking-tight" data-testid="text-summary-docs">{summary.documentCount}</p>
            <p className="text-[10px] text-muted-foreground uppercase tracking-widest font-semibold">Documents</p>
          </div>
          <div className="space-y-1">
            <p className="text-3xl font-bold font-mono text-foreground tracking-tight" data-testid="text-summary-chunks">{summary.chunkCount}</p>
            <p className="text-[10px] text-muted-foreground uppercase tracking-widest font-semibold">Chunks</p>
          </div>
          <div className="space-y-1">
            <p className="text-3xl font-bold font-mono text-foreground tracking-tight" data-testid="text-summary-chars">
              {(summary.characterCount / 1000).toFixed(1)}k
            </p>
            <p className="text-[10px] text-muted-foreground uppercase tracking-widest font-semibold">Characters</p>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

function AddDocumentControls() {
  const [activeTab, setActiveTab] = useState<"upload" | "paste">("upload")

  return (
    <Card className="border-border shadow-sm" data-testid="card-add-document">
      <CardHeader className="pb-4">
        <div className="flex items-center justify-between">
          <div className="space-y-1">
            <CardTitle className="text-base font-semibold">Ingest Content</CardTitle>
            <CardDescription className="text-xs">
              Add files or text to expand the searchable corpus.
            </CardDescription>
          </div>
          <div className="flex bg-muted p-1 rounded-md">
            <button
              onClick={() => setActiveTab("upload")}
              className={`px-3 py-1.5 text-xs font-medium rounded-sm flex items-center gap-2 transition-colors ${
                activeTab === "upload" ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"
              }`}
            >
              <UploadCloud className="h-3.5 w-3.5" />
              File
            </button>
            <button
              onClick={() => setActiveTab("paste")}
              className={`px-3 py-1.5 text-xs font-medium rounded-sm flex items-center gap-2 transition-colors ${
                activeTab === "paste" ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"
              }`}
            >
              <Type className="h-3.5 w-3.5" />
              Text
            </button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {activeTab === "upload" ? <FileUploadView /> : <TextPasteView />}
      </CardContent>
    </Card>
  )
}

function FileUploadView() {
  const queryClient = useQueryClient()
  const uploadDocument = useUploadDocument()
  const fileInputRef = useRef<HTMLInputElement>(null)

  const [isDragging, setIsDragging] = useState(false)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(true)
  }, [])

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)
  }, [])

  const validateAndSetFile = (file: File) => {
    setErrorMsg(null)
    const ext = file.name.split('.').pop()?.toLowerCase()
    const allowedExts = ['md', 'txt', 'pdf', 'html', 'htm', 'docx', 'xlsx', 'xls']

    if (!ext || !allowedExts.includes(ext)) {
      setErrorMsg(`Unsupported format: .${ext}. Allowed: ${allowedExts.join(', ')}`)
      return
    }

    if (file.size > MAX_FILE_SIZE) {
      setErrorMsg(`File too large (${(file.size / 1024 / 1024).toFixed(1)} MB). Max limit is 10 MB.`)
      return
    }

    setSelectedFile(file)
  }

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)
    const file = e.dataTransfer.files?.[0]
    if (file) validateAndSetFile(file)
  }, [])

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) validateAndSetFile(file)
  }

  const handleUpload = () => {
    if (!selectedFile) return
    setErrorMsg(null)

    uploadDocument.mutate({ data: { file: selectedFile } }, {
      onSuccess: () => {
        setSelectedFile(null)
        if (fileInputRef.current) fileInputRef.current.value = ''
        queryClient.invalidateQueries({ queryKey: getListDocumentsQueryKey() })
        queryClient.invalidateQueries({ queryKey: getGetKnowledgeSummaryQueryKey() })
      },
      onError: (err: any) => {
        setErrorMsg(err?.data?.error || err?.message || "Failed to upload document. Please try again.")
      }
    })
  }

  return (
    <div className="space-y-4">
      {!selectedFile ? (
        <div
          className={`border-2 border-dashed rounded-lg p-8 flex flex-col items-center justify-center text-center transition-colors cursor-pointer ${
            isDragging ? "border-primary bg-primary/5" : "border-border hover:border-primary/50 hover:bg-muted/30"
          }`}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
        >
          <div className="bg-muted p-3 rounded-full mb-3">
            <UploadCloud className="h-6 w-6 text-muted-foreground" />
          </div>
          <p className="text-sm font-medium">Click or drag file to upload</p>
          <p className="text-xs text-muted-foreground mt-1 max-w-[250px]">
            Supports .pdf, .docx, .xlsx, .html, .md, .txt (Max 10 MB)
          </p>
          <input
            type="file"
            accept=".md,.txt,.pdf,.html,.htm,.docx,.xlsx,.xls,application/pdf,text/html,text/plain,text/markdown,application/vnd.openxmlformats-officedocument.wordprocessingml.document,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/vnd.ms-excel"
            className="hidden"
            ref={fileInputRef}
            onChange={handleFileSelect}
            data-testid="input-file-upload"
          />
        </div>
      ) : (
        <div className="border border-border rounded-lg p-4 bg-muted/20 space-y-4">
          <div className="flex items-center gap-3">
            <div className="bg-primary/10 p-2 rounded-md text-primary">
              <FileText className="h-5 w-5" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium truncate">{selectedFile.name}</p>
              <p className="text-xs text-muted-foreground font-mono">{(selectedFile.size / 1024).toFixed(1)} KB</p>
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setSelectedFile(null)
                if (fileInputRef.current) fileInputRef.current.value = ''
              }}
              disabled={uploadDocument.isPending}
            >
              Clear
            </Button>
          </div>
          <Button
            className="w-full"
            onClick={handleUpload}
            disabled={uploadDocument.isPending}
          >
            {uploadDocument.isPending ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Extracting & Indexing...
              </>
            ) : (
              <>
                <HardDrive className="mr-2 h-4 w-4" />
                Upload & Process
              </>
            )}
          </Button>
        </div>
      )}

      {errorMsg && (
        <div className="p-3 rounded-md bg-destructive/10 border border-destructive/20 flex gap-2 items-start text-destructive text-sm">
          <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
          <p>{errorMsg}</p>
        </div>
      )}
    </div>
  )
}

function TextPasteView() {
  const queryClient = useQueryClient()
  const createDocument = useCreateDocument()

  const form = useForm<z.infer<typeof createDocSchema>>({
    resolver: zodResolver(createDocSchema),
    defaultValues: {
      name: "",
      content: "",
    },
  })

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
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
        <FormField
          control={form.control}
          name="name"
          render={({ field }) => (
            <FormItem>
              <FormLabel className="text-xs">Identifier</FormLabel>
              <FormControl>
                <Input placeholder="e.g. Architecture RFC 1.0" data-testid="input-doc-name" className="h-9" {...field} />
              </FormControl>
              <FormMessage className="text-xs" />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="content"
          render={({ field }) => (
            <FormItem>
              <FormLabel className="text-xs">Raw Content</FormLabel>
              <FormControl>
                <Textarea
                  placeholder="Paste markdown or plain text here..."
                  className="min-h-[120px] font-mono text-xs resize-y"
                  data-testid="input-doc-content"
                  {...field}
                />
              </FormControl>
              <FormMessage className="text-xs" />
            </FormItem>
          )}
        />
        <div className="flex justify-end">
          <Button type="submit" disabled={createDocument.isPending} data-testid="button-submit-doc" size="sm">
            {createDocument.isPending ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <Plus className="mr-2 h-4 w-4" />
            )}
            Index Text
          </Button>
        </div>
      </form>
    </Form>
  )
}

function getFormatIcon(format: string) {
  switch (format) {
    case 'pdf': return <FileText className="h-4 w-4" />
    case 'html':
    case 'htm': return <FileCode className="h-4 w-4" />
    case 'xlsx':
    case 'xls': return <FileSpreadsheet className="h-4 w-4" />
    case 'md': return <FileJson className="h-4 w-4" />
    default: return <File className="h-4 w-4" />
  }
}

function formatBytes(bytes: number) {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
}

function DocumentList() {
  const { data: documents, isLoading, isError } = useListDocuments({
    query: { queryKey: getListDocumentsQueryKey() }
  })

  if (isLoading) {
    return (
      <div className="space-y-3" data-testid="list-docs-loading">
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-24 w-full" />
      </div>
    )
  }

  if (isError) {
    return (
      <div className="p-4 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm" data-testid="text-docs-error">
        Failed to load corpus documents.
      </div>
    )
  }

  if (!documents || documents.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 px-4 text-center border-2 border-dashed rounded-xl border-border bg-muted/10" data-testid="empty-docs">
        <HardDrive className="h-10 w-10 text-muted-foreground/50 mb-3" />
        <p className="text-sm font-semibold text-foreground">Empty Corpus</p>
        <p className="text-xs text-muted-foreground mt-1 max-w-[200px]">
          Ingest text or files above to construct the searchable index.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-4" data-testid="list-docs">
      <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-widest px-1">Indexed Corpus</h3>
      <div className="space-y-3">
        {documents.map(doc => (
          <Card key={doc.id} className="bg-card shadow-sm border-border hover:border-primary/40 transition-colors group" data-testid={`card-doc-${doc.id}`}>
            <div className="p-4">
              <div className="flex items-start justify-between gap-4 mb-3">
                <div className="flex items-start gap-3 overflow-hidden">
                  <div className="mt-0.5 h-8 w-8 rounded-md bg-secondary flex items-center justify-center shrink-0 text-secondary-foreground">
                    {getFormatIcon(doc.format)}
                  </div>
                  <div className="overflow-hidden">
                    <p className="text-sm font-semibold truncate group-hover:text-primary transition-colors" title={doc.name}>{doc.name}</p>
                    <div className="flex items-center gap-2 mt-1">
                      <Badge variant="outline" className="text-[9px] font-mono py-0 h-4 rounded-sm bg-background">
                        {doc.format.toUpperCase()}
                      </Badge>
                      <span className="text-[10px] text-muted-foreground font-mono">
                        {new Date(doc.createdAt).toLocaleDateString()}
                      </span>
                    </div>
                  </div>
                </div>
                <div className="flex flex-col items-end">
                  <Badge variant="secondary" className="shrink-0 font-mono text-[10px] rounded-sm bg-primary/10 text-primary border-primary/20 hover:bg-primary/20">
                    {doc.chunkCount} chunks
                  </Badge>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-2 pt-3 border-t border-border/50 text-[10px] text-muted-foreground font-mono">
                <div className="flex flex-col">
                  <span className="uppercase tracking-wider opacity-70">Source</span>
                  <span className="text-foreground">{doc.sourceType}</span>
                </div>
                <div className="flex flex-col">
                  <span className="uppercase tracking-wider opacity-70">Size</span>
                  <span className="text-foreground">{formatBytes(doc.sizeBytes)}</span>
                </div>
                <div className="flex flex-col">
                  <span className="uppercase tracking-wider opacity-70">Extracted</span>
                  <span className="text-foreground">{(doc.extractedCharacterCount / 1000).toFixed(1)}k ch</span>
                </div>
              </div>
            </div>
          </Card>
        ))}
      </div>
    </div>
  )
}
