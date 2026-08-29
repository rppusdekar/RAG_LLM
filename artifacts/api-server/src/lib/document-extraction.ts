import path from "node:path";
import { load } from "cheerio";
import mammoth from "mammoth";
import { PDFParse } from "pdf-parse";
import * as XLSX from "xlsx";

export const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;
export const MAX_EXTRACTED_CHARACTERS = 500_000;
const MAX_PDF_PAGES = 250;
const MAX_SPREADSHEET_ROWS_PER_SHEET = 5_000;

export const SUPPORTED_EXTENSIONS = [
  ".txt",
  ".md",
  ".pdf",
  ".html",
  ".htm",
  ".docx",
  ".xlsx",
  ".xls",
] as const;

export type DocumentFormat =
  | "txt"
  | "md"
  | "pdf"
  | "html"
  | "docx"
  | "xlsx"
  | "xls";

export class DocumentExtractionError extends Error {
  constructor(
    message: string,
    readonly statusCode: 400 | 413 | 415 = 400,
  ) {
    super(message);
    this.name = "DocumentExtractionError";
  }
}

export function sanitizeDocumentName(originalName: string): string {
  const name = path
    .basename(originalName)
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .trim();

  if (!name) {
    throw new DocumentExtractionError("The uploaded file must have a valid name.");
  }

  return name.slice(0, 120);
}

export function getDocumentFormat(fileName: string): DocumentFormat {
  const extension = path.extname(fileName).toLowerCase();
  if (!SUPPORTED_EXTENSIONS.includes(extension as (typeof SUPPORTED_EXTENSIONS)[number])) {
    throw new DocumentExtractionError(
      "Unsupported file format. Upload TXT, Markdown, PDF, HTML, DOCX, XLSX, or XLS.",
      415,
    );
  }

  return extension === ".htm"
    ? "html"
    : (extension.slice(1) as DocumentFormat);
}

export async function extractDocumentText(
  buffer: Buffer,
  format: DocumentFormat,
): Promise<string> {
  if (buffer.length === 0) {
    throw new DocumentExtractionError("The uploaded file is empty.");
  }

  validateFileSignature(buffer, format);

  let extracted: string;
  try {
    switch (format) {
      case "txt":
      case "md":
        extracted = decodeText(buffer);
        break;
      case "html":
        extracted = extractHtml(buffer);
        break;
      case "docx":
        extracted = await extractDocx(buffer);
        break;
      case "xlsx":
      case "xls":
        extracted = extractSpreadsheet(buffer);
        break;
      case "pdf":
        extracted = await extractPdf(buffer);
        break;
    }
  } catch (error) {
    if (error instanceof DocumentExtractionError) throw error;
    throw new DocumentExtractionError(
      `Could not read this ${format.toUpperCase()} file. It may be corrupted, encrypted, or unsupported.`,
    );
  }

  const normalized = normalizeExtractedText(extracted);
  if (normalized.length < 20) {
    throw new DocumentExtractionError(
      format === "pdf"
        ? "No usable text was found in this PDF. Scanned PDFs require OCR, which is not enabled."
        : "No usable text was found in the uploaded document.",
    );
  }

  if (normalized.length > MAX_EXTRACTED_CHARACTERS) {
    throw new DocumentExtractionError(
      `The extracted document exceeds ${MAX_EXTRACTED_CHARACTERS.toLocaleString()} characters.`,
      413,
    );
  }

  return normalized;
}

function decodeText(buffer: Buffer): string {
  const text = buffer.toString("utf8").replace(/^\uFEFF/, "");
  if (text.includes("\uFFFD")) {
    throw new DocumentExtractionError(
      "The text encoding could not be read reliably. Please upload a UTF-8 document.",
    );
  }
  return text;
}

function extractHtml(buffer: Buffer): string {
  const $ = load(decodeText(buffer));
  $("script, style, noscript, template, svg").remove();

  const title = $("title").first().text().trim();
  const body = $("body").length > 0 ? $("body").text() : $.root().text();
  return title ? `${title}\n\n${body}` : body;
}

async function extractDocx(buffer: Buffer): Promise<string> {
  const result = await mammoth.extractRawText({ buffer });
  return result.value;
}

function extractSpreadsheet(buffer: Buffer): string {
  const workbook = XLSX.read(buffer, {
    type: "buffer",
    cellDates: true,
    cellFormula: false,
    sheetRows: MAX_SPREADSHEET_ROWS_PER_SHEET,
  });

  if (workbook.SheetNames.length === 0) {
    throw new DocumentExtractionError("The spreadsheet does not contain any worksheets.");
  }

  return workbook.SheetNames.map((sheetName) => {
    const worksheet = workbook.Sheets[sheetName];
    if (!worksheet) return "";

    const rows = XLSX.utils.sheet_to_json<Array<string | number | boolean>>(worksheet, {
      header: 1,
      raw: false,
      defval: "",
      blankrows: false,
    });

    const body = rows
      .map((row, index) => {
        const cells = row.map((cell) => String(cell).trim()).filter(Boolean);
        return cells.length > 0 ? `Row ${index + 1}: ${cells.join(" | ")}` : "";
      })
      .filter(Boolean)
      .join("\n");

    return body ? `Sheet: ${sheetName}\n${body}` : "";
  })
    .filter(Boolean)
    .join("\n\n");
}

async function extractPdf(buffer: Buffer): Promise<string> {
  const parser = new PDFParse({ data: buffer });
  try {
    const info = await parser.getInfo();
    if (info.total > MAX_PDF_PAGES) {
      throw new DocumentExtractionError(
        `This PDF has ${info.total} pages. The current limit is ${MAX_PDF_PAGES} pages.`,
        413,
      );
    }

    const result = await parser.getText();
    return result.pages
      .map((page) => `Page ${page.num}\n${page.text}`)
      .join("\n\n");
  } finally {
    await parser.destroy();
  }
}

function normalizeExtractedText(value: string): string {
  return value
    .replace(/\r\n?/g, "\n")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/[ \t]{2,}/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function validateFileSignature(buffer: Buffer, format: DocumentFormat): void {
  if (format === "pdf" && !buffer.subarray(0, 5).equals(Buffer.from("%PDF-"))) {
    throw new DocumentExtractionError("This file does not contain a valid PDF signature.");
  }

  if (
    (format === "docx" || format === "xlsx") &&
    !buffer.subarray(0, 2).equals(Buffer.from("PK"))
  ) {
    throw new DocumentExtractionError(
      `This file does not contain a valid ${format.toUpperCase()} package.`,
    );
  }

  const oleSignature = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
  if (format === "xls" && !buffer.subarray(0, 8).equals(oleSignature)) {
    throw new DocumentExtractionError("This file does not contain a valid XLS workbook.");
  }
}