---
name: PDF parser bundling
description: Runtime packaging constraint for server-side PDF text extraction.
---

Keep `pdf-parse`, `pdfjs-dist`, and `@napi-rs/canvas` external to the bundled API output, and keep the native canvas package available as a direct runtime dependency.

**Why:** Bundling PDF.js relocates its worker/native-canvas resolution. The API can build successfully but then reject valid PDFs or fail at startup because browser canvas globals are missing.

**How to apply:** Preserve these runtime externals when changing the server build pipeline or upgrading the PDF extraction dependency, and verify a real selectable-text PDF after such changes.