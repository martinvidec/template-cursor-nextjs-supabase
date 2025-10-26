# Security Audit Report
**Datum:** 26. Oktober 2025
**Projekt:** Next.js 14 + Supabase Template
**Version:** 0.1.0
**Audit-Typ:** Umfassende Sicherheitsanalyse

---

## Executive Summary

Dieses Security Audit identifiziert **14 kritische und hochgradige Sicherheitslücken** in der Codebase. Das Projekt ist ein Next.js 14 Template mit Supabase-Integration, das AI-APIs (OpenAI, Anthropic, Replicate, Deepgram) verwendet.

### Kritische Probleme (Sofortige Maßnahmen erforderlich):
- **API-Schlüssel-Exposition** an Client-Seite (Deepgram)
- **Fehlende Authentifizierungsprüfungen** auf allen AI-API-Endpunkten
- **Keine Row-Level Security (RLS)** Implementierung sichtbar
- **Unvalidierte Benutzereingaben** in Datenbankabfragen
- **Dependency-Schwachstellen** mit moderater Schwere

### Risiko-Bewertung:
- 🔴 **Kritisch:** 3 Probleme
- 🟠 **Hoch:** 5 Probleme
- 🟡 **Mittel:** 4 Probleme
- 🟢 **Niedrig:** 2 Probleme

---

## 1. Kritische Sicherheitslücken (Critical)

### 🔴 1.1 API-Schlüssel-Exposition - Deepgram

**Datei:** `src/app/api/deepgram/route.ts:7`

**Problem:**
```typescript
export async function GET() {
    return NextResponse.json({
      key: process.env.DEEPGRAM_API_KEY ?? "",
    });
}
```

Der Deepgram API-Schlüssel wird direkt an den Client zurückgegeben, ohne jegliche Authentifizierung oder Autorisierung.

**Risiko:**
- Jeder kann den API-Schlüssel abfangen und für eigene Zwecke missbrauchen
- Unbegrenzte API-Nutzung auf Kosten des Projekts
- Potenzielle Datenlecks durch unbefugten Zugriff auf Deepgram-Dienste

**Empfehlung:**
```typescript
// NICHT IMPLEMENTIEREN - Schlüssel sollten nie exponiert werden
// Stattdessen: Server-Side Proxy implementieren

import { createClient } from '@supabase/supabase-js'
import { cookies } from 'next/headers'

export async function GET() {
  // Authentifizierung prüfen
  const cookieStore = cookies()
  const supabase = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    { cookies: () => cookieStore }
  )

  const { data: { user }, error } = await supabase.auth.getUser()

  if (error || !user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  // Verwenden Sie stattdessen einen Server-Side Deepgram Proxy
  // oder generieren Sie temporäre, eingeschränkte Tokens
  const temporaryToken = await generateTemporaryDeepgramToken(user.id)

  return NextResponse.json({ token: temporaryToken })
}
```

**CVSS Score:** 9.1 (Critical)
**CWE:** CWE-200 (Exposure of Sensitive Information)

---

### 🔴 1.2 Fehlende Authentifizierung auf AI-API-Endpunkten

**Betroffene Dateien:**
- `src/app/api/openai/chat/route.ts`
- `src/app/api/anthropic/chat/route.ts`
- `src/app/api/replicate/generate-image/route.ts`
- `src/app/api/openai/transcribe/route.ts`

**Problem:**
Alle AI-API-Endpunkte haben keine Authentifizierungsprüfung. Jeder mit Zugriff auf die URL kann die APIs nutzen.

**Beispiel (`src/app/api/openai/chat/route.ts:6`):**
```typescript
export async function POST(req: Request) {
  const { messages } = await req.json();  // Keine Auth-Prüfung!
  const result = await streamText({
    model: openai("gpt-4o"),
    messages: convertToCoreMessages(messages),
    system: "You are a helpful AI assistant",
  });
  return result.toDataStreamResponse();
}
```

**Risiko:**
- Unbefugter Zugriff auf teure AI-APIs (GPT-4, Claude, etc.)
- Massive API-Kosten durch Missbrauch
- DoS-Angriffe möglich durch exzessive Anfragen
- Datenlecks, wenn sensible Informationen in Prompts enthalten sind

**Empfehlung:**
```typescript
import { createClient } from '@supabase/supabase-js'
import { cookies } from 'next/headers'

export async function POST(req: Request) {
  // 1. Authentifizierung prüfen
  const cookieStore = cookies()
  const supabase = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    { cookies: () => cookieStore }
  )

  const { data: { user }, error } = await supabase.auth.getUser()

  if (error || !user) {
    return NextResponse.json(
      { error: 'Authentication required' },
      { status: 401 }
    )
  }

  // 2. Rate Limiting prüfen (z.B. mit Upstash Redis)
  const rateLimitResult = await checkRateLimit(user.id)
  if (!rateLimitResult.success) {
    return NextResponse.json(
      { error: 'Rate limit exceeded' },
      { status: 429 }
    )
  }

  // 3. Input Validierung
  const { messages } = await req.json()
  if (!Array.isArray(messages) || messages.length === 0) {
    return NextResponse.json(
      { error: 'Invalid messages format' },
      { status: 400 }
    )
  }

  // 4. API-Aufruf mit Error Handling
  try {
    const result = await streamText({
      model: openai("gpt-4o"),
      messages: convertToCoreMessages(messages),
      system: "You are a helpful AI assistant",
    })
    return result.toDataStreamResponse()
  } catch (error) {
    console.error('OpenAI API Error:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}
```

**CVSS Score:** 8.6 (High)
**CWE:** CWE-306 (Missing Authentication for Critical Function)

---

### 🔴 1.3 Unsichere Datei-Operationen in Transcription API

**Datei:** `src/app/api/openai/transcribe/route.ts:24-39`

**Problem:**
```typescript
const filePath = "tmp/input.wav";

try {
  // Synchrone Datei-Operationen
  fs.writeFileSync(filePath, new Uint8Array(audio));
  const readStream = fs.createReadStream(filePath);

  const data = await openai.audio.transcriptions.create({
    file: readStream,
    model: "whisper-1",
  });

  // Cleanup nur bei Erfolg
  fs.unlinkSync(filePath);
  return NextResponse.json(data);
} catch (error) {
  console.error("Error processing audio:", error);
  return NextResponse.error();  // Datei wird nicht gelöscht!
}
```

**Risiken:**
1. **Race Condition:** Mehrere gleichzeitige Anfragen überschreiben dieselbe Datei
2. **Dateilecks:** Bei Fehler werden temporäre Dateien nicht gelöscht
3. **Path Traversal potenzial:** Fest kodierter Pfad, aber gefährlich bei späteren Änderungen
4. **Synchrone I/O:** Blockiert Event Loop in Node.js
5. **Keine Größenbeschränkung:** Große Audio-Dateien können Server überlasten

**Empfehlung:**
```typescript
import { randomUUID } from 'crypto'
import { unlink } from 'fs/promises'
import path from 'path'

export async function POST(req: Request) {
  // ... Auth-Prüfung ...

  const body = await req.json()
  const base64Audio = body.audio

  // 1. Größenvalidierung
  const audioBuffer = Buffer.from(base64Audio, "base64")
  const maxSize = 25 * 1024 * 1024 // 25MB (Whisper API Limit)

  if (audioBuffer.length > maxSize) {
    return NextResponse.json(
      { error: 'Audio file too large' },
      { status: 400 }
    )
  }

  // 2. Eindeutiger Dateiname mit UUID
  const fileName = `${randomUUID()}.wav`
  const filePath = path.join(process.cwd(), 'tmp', fileName)

  let fileHandle
  try {
    // 3. Asynchrone Datei-Operationen
    await fs.promises.writeFile(filePath, audioBuffer)

    const readStream = fs.createReadStream(filePath)
    const data = await openai.audio.transcriptions.create({
      file: readStream,
      model: "whisper-1",
    })

    return NextResponse.json(data)
  } catch (error) {
    console.error("Error processing audio:", error)
    return NextResponse.json(
      { error: 'Failed to process audio' },
      { status: 500 }
    )
  } finally {
    // 4. Cleanup in finally-Block (wird immer ausgeführt)
    try {
      await unlink(filePath)
    } catch (unlinkError) {
      console.error('Error cleaning up temp file:', unlinkError)
    }
  }
}
```

**CVSS Score:** 7.5 (High)
**CWE:** CWE-377 (Insecure Temporary File), CWE-362 (Race Condition)

---

## 2. Hochgradige Sicherheitslücken (High)

### 🟠 2.1 Fehlende Row-Level Security (RLS) Enforcement

**Betroffene Datei:** `src/lib/supabase/supabaseUtils.ts`

**Problem:**
Alle Datenbankfunktionen verwenden den Anon-Key ohne sichtbare RLS-Policies:

```typescript
export const getDocuments = async (tableName: string) => {
  const { data, error } = await supabase
    .from(tableName)
    .select('*')  // Gibt ALLE Dokumente zurück, unabhängig vom Benutzer

  return data || []
}
```

**Risiko:**
- Benutzer können auf alle Daten in der Datenbank zugreifen
- Horizontale Privilegieneskalation
- Datenschutzverletzungen (DSGVO)
- Potenzielle Datenmanipulation anderer Benutzer

**Empfehlung:**

**1. RLS in Supabase aktivieren (SQL):**
```sql
-- Für Beispiel-Tabelle "notes"
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;

-- Policy: Benutzer können nur ihre eigenen Notizen sehen
CREATE POLICY "Users can view their own notes"
ON notes FOR SELECT
USING (auth.uid() = user_id);

-- Policy: Benutzer können nur ihre eigenen Notizen einfügen
CREATE POLICY "Users can insert their own notes"
ON notes FOR INSERT
WITH CHECK (auth.uid() = user_id);

-- Policy: Benutzer können nur ihre eigenen Notizen aktualisieren
CREATE POLICY "Users can update their own notes"
ON notes FOR UPDATE
USING (auth.uid() = user_id);

-- Policy: Benutzer können nur ihre eigenen Notizen löschen
CREATE POLICY "Users can delete their own notes"
ON notes FOR DELETE
USING (auth.uid() = user_id);
```

**2. Server-Side Supabase Client verwenden:**
```typescript
// Neue Datei: src/lib/supabase/server.ts
import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'

export function createClient() {
  const cookieStore = cookies()

  return createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        get(name: string) {
          return cookieStore.get(name)?.value
        },
      },
    }
  )
}
```

**3. Datenbankfunktionen aktualisieren:**
```typescript
import { createClient } from './server'

export const getDocuments = async (tableName: string) => {
  const supabase = createClient()

  // RLS wird automatisch durchgesetzt basierend auf dem authentifizierten Benutzer
  const { data, error } = await supabase
    .from(tableName)
    .select('*')

  if (error) {
    console.error('Error getting documents:', error)
    throw error
  }

  return data || []
}
```

**CVSS Score:** 8.1 (High)
**CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)

---

### 🟠 2.2 Keine Input-Validierung in Datenbankfunktionen

**Betroffene Datei:** `src/lib/supabase/supabaseUtils.ts:29-42`

**Problem:**
```typescript
export const addDocument = async (tableName: string, data: any) => {
  const { data: result, error } = await supabase
    .from(tableName)  // Keine Validierung von tableName!
    .insert(data)      // Keine Validierung von data!
    .select()
    .single()

  return result
}
```

**Risiken:**
- **SQL Injection:** Durch ungültige Tabellennamen
- **NoSQL Injection:** Durch manipulierte Datenobjekte
- **Daten-Inkonsistenz:** Fehlende oder falsche Felder
- **Type Confusion:** TypeScript `any` deaktiviert Type Safety

**Empfehlung:**
```typescript
import { z } from 'zod'

// 1. Whitelist erlaubter Tabellen
const ALLOWED_TABLES = ['notes', 'posts', 'comments', 'profiles'] as const
type AllowedTable = typeof ALLOWED_TABLES[number]

function isAllowedTable(table: string): table is AllowedTable {
  return ALLOWED_TABLES.includes(table as AllowedTable)
}

// 2. Schema-Validierung mit Zod
const noteSchema = z.object({
  text: z.string().min(1).max(10000),
  timestamp: z.string().datetime(),
  user_id: z.string().uuid().optional(),
})

const postSchema = z.object({
  title: z.string().min(1).max(200),
  content: z.string().min(1).max(50000),
  image_url: z.string().url().optional(),
  user_id: z.string().uuid().optional(),
})

const schemas = {
  notes: noteSchema,
  posts: postSchema,
  // ... weitere Schemas
}

// 3. Typsichere Funktion
export const addDocument = async <T extends AllowedTable>(
  tableName: T,
  data: z.infer<typeof schemas[T]>
) => {
  // Tabellenname validieren
  if (!isAllowedTable(tableName)) {
    throw new Error(`Invalid table name: ${tableName}`)
  }

  // Daten validieren
  const schema = schemas[tableName]
  const validatedData = schema.parse(data)

  // Daten einfügen
  const { data: result, error } = await supabase
    .from(tableName)
    .insert(validatedData)
    .select()
    .single()

  if (error) {
    console.error('Error adding document:', error)
    throw error
  }

  return result
}
```

**Installation:**
```bash
npm install zod
```

**CVSS Score:** 7.3 (High)
**CWE:** CWE-20 (Improper Input Validation)

---

### 🟠 2.3 Open Redirect Vulnerability im Auth Callback

**Datei:** `src/app/auth/callback/route.ts:8`

**Problem:**
```typescript
export async function GET(request: NextRequest) {
  const { searchParams, origin } = new URL(request.url)
  const code = searchParams.get('code')
  const next = searchParams.get('next') ?? '/'  // Unvalidiert!

  if (code) {
    const { error } = await supabase.auth.exchangeCodeForSession(code)
    if (!error) {
      return NextResponse.redirect(`${origin}${next}`)  // Open Redirect!
    }
  }

  return NextResponse.redirect(`${origin}/auth/auth-code-error`)
}
```

**Risiko:**
Ein Angreifer kann einen Link erstellen wie:
```
https://ihre-app.com/auth/callback?code=...&next=https://evil.com/phishing
```

Nach erfolgreicher Authentifizierung wird der Benutzer zu `evil.com` weitergeleitet.

**Empfehlung:**
```typescript
import { NextRequest, NextResponse } from 'next/server'
import { supabase } from '@/lib/supabase/supabase'

// Whitelist erlaubter Redirect-Pfade
const ALLOWED_REDIRECTS = [
  '/',
  '/dashboard',
  '/profile',
  '/settings',
  '/chat',
  '/images',
  '/notes',
]

function isValidRedirect(path: string): boolean {
  // 1. Muss mit / beginnen (keine externen URLs)
  if (!path.startsWith('/')) return false

  // 2. Darf nicht mit // beginnen (protocol-relative URLs)
  if (path.startsWith('//')) return false

  // 3. Muss in Whitelist sein oder Subpath davon
  return ALLOWED_REDIRECTS.some(allowed =>
    path === allowed || path.startsWith(`${allowed}/`)
  )
}

export async function GET(request: NextRequest) {
  const { searchParams, origin } = new URL(request.url)
  const code = searchParams.get('code')
  const next = searchParams.get('next') ?? '/'

  // Redirect-Pfad validieren
  const redirectPath = isValidRedirect(next) ? next : '/'

  if (code) {
    const { error } = await supabase.auth.exchangeCodeForSession(code)
    if (!error) {
      return NextResponse.redirect(`${origin}${redirectPath}`)
    }
  }

  return NextResponse.redirect(`${origin}/auth/auth-code-error`)
}
```

**CVSS Score:** 6.1 (Medium/High)
**CWE:** CWE-601 (URL Redirection to Untrusted Site - Open Redirect)

---

### 🟠 2.4 Fehlende Content Security Policy (CSP)

**Betroffene Datei:** `next.config.mjs`

**Problem:**
Die aktuelle CSP ist nur für SVG-Bilder definiert:
```javascript
contentSecurityPolicy: "default-src 'self'; script-src 'none'; sandbox;",
```

Diese CSP gilt nur für Remote-Bilder, nicht für die gesamte Anwendung.

**Risiko:**
- **XSS-Angriffe** durch fehlende Script-Einschränkungen
- **Data Exfiltration** durch fehlende connect-src Beschränkungen
- **Clickjacking** durch fehlende frame-ancestors
- **MIME-Type Sniffing** Angriffe

**Empfehlung:**

**1. Next.js Middleware für Security Headers:**
```typescript
// Neue Datei: middleware.ts
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export function middleware(request: NextRequest) {
  const response = NextResponse.next()

  // Content Security Policy
  response.headers.set(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self' 'unsafe-eval' 'unsafe-inline'", // Next.js benötigt unsafe-eval
      "style-src 'self' 'unsafe-inline'", // Tailwind benötigt unsafe-inline
      "img-src 'self' data: https:",
      "font-src 'self' data:",
      "connect-src 'self' https://api.openai.com https://api.anthropic.com https://api.replicate.com https://api.deepgram.com https://*.supabase.co wss://*.supabase.co wss://api.deepgram.com",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join('; ')
  )

  // Weitere Security Headers
  response.headers.set('X-Frame-Options', 'DENY')
  response.headers.set('X-Content-Type-Options', 'nosniff')
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin')
  response.headers.set(
    'Permissions-Policy',
    'camera=(), microphone=(self), geolocation=()'
  )
  response.headers.set(
    'Strict-Transport-Security',
    'max-age=31536000; includeSubDomains'
  )

  return response
}

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
}
```

**2. Alternativ in `next.config.mjs`:**
```javascript
const nextConfig = {
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin',
          },
          {
            key: 'Permissions-Policy',
            value: 'camera=(), microphone=(self), geolocation=()',
          },
        ],
      },
    ]
  },
}
```

**CVSS Score:** 6.5 (Medium)
**CWE:** CWE-1021 (Improper Restriction of Rendered UI Layers)

---

### 🟠 2.5 Dependency Vulnerabilities

**Problem:**
NPM Audit zeigt moderate Schwachstellen in AI SDK Paketen:

```
@ai-sdk/anthropic: moderate severity (<=0.0.51)
@ai-sdk/openai: moderate severity (<=0.0.68)
@ai-sdk/provider-utils: moderate severity (<=1.0.20)
```

Die Schwachstelle bezieht sich auf die `nanoid` Bibliothek in `@ai-sdk/provider-utils`.

**Risiko:**
- Bekannte Sicherheitslücken in Abhängigkeiten
- Potenzielle Ausnutzung durch Angreifer
- Compliance-Probleme

**Empfehlung:**

**1. Sofortiges Update:**
```bash
npm install @ai-sdk/openai@latest @ai-sdk/anthropic@latest
```

**Achtung:** Dies sind Major-Version-Updates (v2.x). Prüfen Sie Breaking Changes:
- https://github.com/vercel/ai/releases

**2. Automated Dependency Scanning einrichten:**

**.github/workflows/dependency-check.yml:**
```yaml
name: Dependency Security Check

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * 0'  # Wöchentlich

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '20'
      - run: npm audit --audit-level=moderate
      - run: npm outdated || true
```

**3. Dependabot aktivieren (.github/dependabot.yml):**
```yaml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    reviewers:
      - "security-team"
    labels:
      - "dependencies"
      - "security"
```

**CVSS Score:** 5.3 (Medium)
**CWE:** CWE-1104 (Use of Unmaintained Third Party Components)

---

## 3. Mittlere Sicherheitslücken (Medium)

### 🟡 3.1 Fehlendes Rate Limiting

**Problem:**
Keine Rate-Limiting-Implementierung auf API-Endpunkten sichtbar.

**Risiko:**
- DoS-Angriffe durch exzessive Anfragen
- API-Kosten-Explosion bei AI-Diensten
- Brute-Force-Angriffe auf Auth-Endpunkte

**Empfehlung:**

**Option 1: Upstash Redis (Empfohlen für Serverless):**
```bash
npm install @upstash/ratelimit @upstash/redis
```

```typescript
// lib/rate-limit.ts
import { Ratelimit } from '@upstash/ratelimit'
import { Redis } from '@upstash/redis'

export const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(10, '10 s'), // 10 requests per 10 seconds
  analytics: true,
})

// In API Route:
export async function POST(req: Request) {
  const ip = req.headers.get('x-forwarded-for') ?? 'unknown'
  const { success, reset } = await ratelimit.limit(ip)

  if (!success) {
    return NextResponse.json(
      { error: 'Rate limit exceeded', resetAt: reset },
      { status: 429 }
    )
  }

  // ... Rest der Logik
}
```

**Option 2: Vercel Edge Middleware:**
```typescript
// middleware.ts
import { Ratelimit } from '@upstash/ratelimit'
import { Redis } from '@upstash/redis'

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(10, '10 s'),
})

export async function middleware(request: NextRequest) {
  if (request.nextUrl.pathname.startsWith('/api/')) {
    const ip = request.ip ?? '127.0.0.1'
    const { success } = await ratelimit.limit(ip)

    if (!success) {
      return NextResponse.json(
        { error: 'Too many requests' },
        { status: 429 }
      )
    }
  }

  return NextResponse.next()
}
```

**CVSS Score:** 5.3 (Medium)
**CWE:** CWE-770 (Allocation of Resources Without Limits)

---

### 🟡 3.2 Fehlendes Error Logging und Monitoring

**Problem:**
Alle Fehler werden nur in `console.error()` geloggt, keine zentrale Fehlerbehandlung.

**Beispiel:**
```typescript
if (error) {
  console.error('Error signing out:', error)  // Nur Console
  throw error
}
```

**Risiko:**
- Keine Sichtbarkeit von Sicherheitsvorfällen
- Fehlende Audit-Trails
- Verzögerte Reaktion auf Angriffe
- Compliance-Probleme (DSGVO, etc.)

**Empfehlung:**

**Option 1: Sentry Integration:**
```bash
npm install @sentry/nextjs
```

```typescript
// sentry.client.config.ts
import * as Sentry from '@sentry/nextjs'

Sentry.init({
  dsn: process.env.NEXT_PUBLIC_SENTRY_DSN,
  tracesSampleRate: 1.0,
  environment: process.env.NODE_ENV,
  beforeSend(event, hint) {
    // Filtere sensible Daten
    if (event.request) {
      delete event.request.cookies
      delete event.request.headers
    }
    return event
  },
})
```

**Option 2: Custom Error Handler:**
```typescript
// lib/error-handler.ts
import { User } from '@supabase/supabase-js'

interface ErrorContext {
  user?: User
  action: string
  metadata?: Record<string, any>
}

export function logSecurityEvent(
  error: Error,
  context: ErrorContext
) {
  // 1. Console Log (Development)
  if (process.env.NODE_ENV === 'development') {
    console.error('Security Event:', {
      error: error.message,
      stack: error.stack,
      ...context,
    })
  }

  // 2. External Service (Production)
  if (process.env.NODE_ENV === 'production') {
    // Senden an Logging-Service (Sentry, LogRocket, etc.)
    // sendToLoggingService(error, context)
  }

  // 3. Database Audit Log
  // saveToAuditLog({
  //   timestamp: new Date().toISOString(),
  //   userId: context.user?.id,
  //   action: context.action,
  //   error: error.message,
  //   metadata: context.metadata,
  // })
}

// Verwendung:
try {
  await supabase.auth.signOut()
} catch (error) {
  logSecurityEvent(error as Error, {
    user,
    action: 'sign_out',
    metadata: { timestamp: Date.now() }
  })
  throw error
}
```

**CVSS Score:** 4.3 (Medium)
**CWE:** CWE-778 (Insufficient Logging)

---

### 🟡 3.3 Unsichere OAuth Redirect Configuration

**Datei:** `src/lib/contexts/AuthContext.tsx:48`

**Problem:**
```typescript
const signInWithGoogle = async () => {
  try {
    const { error } = await supabase.auth.signInWithOAuth({
      provider: 'google',
      options: {
        redirectTo: `${window.location.origin}/auth/callback`  // Dynamisch!
      }
    });
  }
}
```

**Risiko:**
Wenn die App über verschiedene Domains erreichbar ist (z.B. Staging, Review Apps), könnte ein Angreifer über eine nicht autorisierte Domain eine OAuth-Anfrage starten.

**Empfehlung:**

**1. Hardcodierte Redirect URL:**
```typescript
const ALLOWED_ORIGINS = [
  'https://your-app.com',
  'https://staging.your-app.com',
  'http://localhost:3000', // Development
]

const signInWithGoogle = async () => {
  const currentOrigin = window.location.origin

  // Prüfe ob Origin erlaubt ist
  const redirectTo = ALLOWED_ORIGINS.includes(currentOrigin)
    ? `${currentOrigin}/auth/callback`
    : 'https://your-app.com/auth/callback' // Fallback zu Production

  const { error } = await supabase.auth.signInWithOAuth({
    provider: 'google',
    options: { redirectTo }
  })
}
```

**2. Environment Variable verwenden:**
```typescript
// .env.local
NEXT_PUBLIC_APP_URL=https://your-app.com

// AuthContext.tsx
const signInWithGoogle = async () => {
  const { error } = await supabase.auth.signInWithOAuth({
    provider: 'google',
    options: {
      redirectTo: `${process.env.NEXT_PUBLIC_APP_URL}/auth/callback`
    }
  })
}
```

**3. Supabase Dashboard konfigurieren:**
In Supabase Dashboard → Authentication → URL Configuration:
- Fügen Sie nur vertrauenswürdige Redirect URLs hinzu
- Wildcard-Domains vermeiden

**CVSS Score:** 5.4 (Medium)
**CWE:** CWE-601 (URL Redirection to Untrusted Site)

---

### 🟡 3.4 Fehlende CORS-Konfiguration

**Problem:**
Keine explizite CORS-Konfiguration in `next.config.mjs` oder API-Routes.

**Risiko:**
- Unerwünschte Cross-Origin-Requests
- CSRF-Angriffe
- API-Missbrauch von externen Domains

**Empfehlung:**

**Option 1: Middleware CORS Handler:**
```typescript
// middleware.ts
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

const ALLOWED_ORIGINS = [
  'https://your-app.com',
  'https://staging.your-app.com',
  process.env.NODE_ENV === 'development' ? 'http://localhost:3000' : '',
].filter(Boolean)

export function middleware(request: NextRequest) {
  const origin = request.headers.get('origin')
  const response = NextResponse.next()

  // CORS für API Routes
  if (request.nextUrl.pathname.startsWith('/api/')) {
    if (origin && ALLOWED_ORIGINS.includes(origin)) {
      response.headers.set('Access-Control-Allow-Origin', origin)
    } else {
      response.headers.set('Access-Control-Allow-Origin', ALLOWED_ORIGINS[0])
    }

    response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
    response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    response.headers.set('Access-Control-Max-Age', '86400')
  }

  return response
}
```

**Option 2: Per-Route CORS (für spezielle APIs):**
```typescript
// api/openai/chat/route.ts
export async function OPTIONS(request: Request) {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': 'https://your-app.com',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Max-Age': '86400',
    },
  })
}

export async function POST(req: Request) {
  // Verify origin
  const origin = req.headers.get('origin')
  if (origin && !ALLOWED_ORIGINS.includes(origin)) {
    return NextResponse.json(
      { error: 'Forbidden' },
      { status: 403 }
    )
  }

  // ... Rest der Logik
}
```

**CVSS Score:** 5.0 (Medium)
**CWE:** CWE-346 (Origin Validation Error)

---

## 4. Niedrige Sicherheitslücken (Low)

### 🟢 4.1 Übermäßige Error-Informationen in Responses

**Problem:**
Fehler-Details werden direkt an den Client zurückgegeben:

```typescript
// api/replicate/generate-image/route.ts:35
return NextResponse.json({ error: (error as Error).message }, { status: 500 })
```

**Risiko:**
- Information Disclosure über interne Systeme
- Stack Traces könnten exponiert werden
- Hilft Angreifern bei Reconnaissance

**Empfehlung:**
```typescript
export async function POST(request: Request) {
  try {
    const output = await replicate.run(...)
    return NextResponse.json({ output }, { status: 200 })
  } catch (error) {
    // Detaillierter Log für Entwickler
    console.error("Replicate API Error:", {
      message: (error as Error).message,
      stack: (error as Error).stack,
      timestamp: new Date().toISOString(),
    })

    // Generische Nachricht für Client
    return NextResponse.json(
      {
        error: 'Failed to generate image. Please try again later.',
        code: 'IMAGE_GENERATION_FAILED'
      },
      { status: 500 }
    )
  }
}
```

**CVSS Score:** 3.7 (Low)
**CWE:** CWE-209 (Generation of Error Message with Sensitive Information)

---

### 🟢 4.2 Fehlende Security.txt

**Problem:**
Keine `/public/security.txt` oder `/.well-known/security.txt` Datei.

**Risiko:**
- Security Researcher können keine Schwachstellen melden
- Keine koordinierte Offenlegung von Sicherheitslücken
- Compliance-Anforderungen nicht erfüllt

**Empfehlung:**

**Datei: `public/.well-known/security.txt`:**
```
Contact: mailto:security@your-domain.com
Expires: 2026-12-31T23:59:59.000Z
Preferred-Languages: en, de
Canonical: https://your-app.com/.well-known/security.txt

# Unsere Security Policy
Policy: https://your-app.com/security-policy

# PGP Key für verschlüsselte Kommunikation
Encryption: https://your-app.com/pgp-key.txt

# Responsible Disclosure
Acknowledgments: https://your-app.com/security-hall-of-fame
```

**RFC 9116 Standard:** https://www.rfc-editor.org/rfc/rfc9116.html

**CVSS Score:** 0.0 (Informational)
**CWE:** N/A (Best Practice)

---

## 5. Positive Sicherheitsbefunde

Die folgenden Sicherheitsmaßnahmen sind bereits korrekt implementiert:

✅ **Environment Variables:**
- `.env.example` vorhanden mit klaren Beispielen
- `.gitignore` verhindert Commit von Secrets
- `NEXT_PUBLIC_*` Präfix korrekt für client-exposed Variablen

✅ **TypeScript:**
- Strict Mode aktiviert in `tsconfig.json`
- Type Safety in großen Teilen der Codebase

✅ **OAuth Implementation:**
- Verwendet Supabase's sichere OAuth-Implementierung
- PKCE flow automatisch von Supabase gehandhabt

✅ **Remote Images:**
- Whitelist-basierte Konfiguration in `next.config.mjs`
- SVG mit restriktiver CSP

✅ **Git Security:**
- Keine hardcodierten Secrets im Code
- Keine Credential-Files in Git-Historie

---

## 6. Compliance und Regulatorische Überlegungen

### DSGVO (GDPR)
- ❌ Fehlende Audit Logs für Datenzugriffe
- ❌ Keine Datenminimierung sichtbar
- ❌ Keine explizite Einwilligung für AI-Verarbeitung
- ⚠️ OAuth Daten (Google) müssen transparent kommuniziert werden

### OWASP Top 10 (2021)
1. ✅ **A01:2021 – Broken Access Control:** Teilweise (RLS fehlt)
2. ❌ **A02:2021 – Cryptographic Failures:** Keine Verschlüsselung sichtbar
3. ❌ **A03:2021 – Injection:** Input-Validierung fehlt
4. ✅ **A04:2021 – Insecure Design:** Gute Architektur-Grundlage
5. ❌ **A05:2021 – Security Misconfiguration:** Mehrere Punkte (CSP, etc.)
6. ❌ **A06:2021 – Vulnerable Components:** Dependency-Schwachstellen
7. ❌ **A07:2021 – Identification & Authentication Failures:** Auth auf APIs fehlt
8. ⚠️ **A08:2021 – Software and Data Integrity Failures:** Teilweise
9. ❌ **A09:2021 – Security Logging & Monitoring Failures:** Nicht implementiert
10. ❌ **A10:2021 – Server-Side Request Forgery:** Nicht getestet

**Score: 3/10** (30% OWASP Compliance)

---

## 7. Empfohlene Sofortmaßnahmen (Priorisiert)

### Woche 1 (Kritisch):
1. ✅ **Deepgram API Key Endpunkt entfernen** oder Auth hinzufügen
2. ✅ **Authentifizierung zu allen AI-API-Routen hinzufügen**
3. ✅ **RLS in Supabase aktivieren** für alle Tabellen
4. ✅ **Input-Validierung** mit Zod implementieren

### Woche 2 (Hoch):
5. ✅ **Temporäre Datei-Handhabung** in Transcribe API fixen
6. ✅ **Open Redirect** in Auth Callback fixen
7. ✅ **Security Headers** via Middleware hinzufügen
8. ✅ **Dependencies updaten** (@ai-sdk/*)

### Woche 3 (Mittel):
9. ✅ **Rate Limiting** implementieren (Upstash)
10. ✅ **Error Logging** mit Sentry einrichten
11. ✅ **CORS-Konfiguration** hinzufügen
12. ✅ **OAuth Redirect Whitelist** implementieren

### Woche 4 (Niedrig & Best Practices):
13. ✅ **Error Messages** generisch machen
14. ✅ **Security.txt** erstellen
15. ✅ **Security Testing** einrichten (GitHub Actions)
16. ✅ **Documentation** aktualisieren

---

## 8. Security Testing Empfehlungen

### Automatisierte Tests:

**1. SAST (Static Application Security Testing):**
```bash
npm install --save-dev eslint-plugin-security
```

```json
// .eslintrc.json
{
  "extends": ["next/core-web-vitals"],
  "plugins": ["security"],
  "rules": {
    "security/detect-object-injection": "warn",
    "security/detect-non-literal-regexp": "warn",
    "security/detect-unsafe-regex": "error",
    "security/detect-buffer-noassert": "error",
    "security/detect-eval-with-expression": "error",
    "security/detect-no-csrf-before-method-override": "error"
  }
}
```

**2. Dependency Scanning:**
```bash
# Wöchentlich ausführen
npm audit
npm outdated

# Oder mit Snyk
npx snyk test
```

**3. Secret Scanning:**
```bash
# TruffleHog installation
pip install truffleHog

# Scan Git-Historie
trufflehog --regex --entropy=True .
```

### Manuelle Tests:

**Penetration Testing Checkliste:**
- [ ] SQL/NoSQL Injection Testing
- [ ] XSS (Reflected, Stored, DOM-based)
- [ ] CSRF Token Validation
- [ ] Authentication Bypass
- [ ] Authorization Testing (Horizontal/Vertical Privilege Escalation)
- [ ] Session Management
- [ ] File Upload Security
- [ ] API Rate Limiting
- [ ] Error Handling
- [ ] Input Validation

**Tools:**
- OWASP ZAP
- Burp Suite
- Postman (API Testing)
- Browser DevTools

---

## 9. Security Monitoring Setup

### Empfohlene Tools:

**Application Monitoring:**
- **Sentry:** Error Tracking & Performance
- **LogRocket:** Session Replay für Debugging
- **Vercel Analytics:** Performance Monitoring

**Infrastructure Monitoring:**
- **Supabase Dashboard:** Database Logs & Auth Events
- **Vercel Logs:** Deployment & Runtime Logs
- **Uptime Robot:** Availability Monitoring

**Security Monitoring:**
- **GitHub Dependabot:** Dependency Alerts
- **Snyk:** Continuous Vulnerability Scanning
- **GitGuardian:** Secret Detection in Commits

### Alert Configuration:

```typescript
// lib/alerts.ts
export async function sendSecurityAlert(event: {
  severity: 'critical' | 'high' | 'medium' | 'low'
  title: string
  description: string
  metadata?: Record<string, any>
}) {
  // 1. Sentry Alert
  if (process.env.NODE_ENV === 'production') {
    Sentry.captureException(new Error(event.title), {
      level: event.severity === 'critical' ? 'error' : 'warning',
      extra: event.metadata,
    })
  }

  // 2. Slack/Discord Webhook (für Critical Events)
  if (event.severity === 'critical' && process.env.SLACK_WEBHOOK_URL) {
    await fetch(process.env.SLACK_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text: `🚨 Security Alert: ${event.title}`,
        attachments: [{
          color: 'danger',
          text: event.description,
          fields: Object.entries(event.metadata || {}).map(([key, value]) => ({
            title: key,
            value: String(value),
            short: true,
          })),
        }],
      }),
    })
  }

  // 3. Database Audit Log
  // await supabase.from('security_events').insert(event)
}
```

---

## 10. Zusammenfassung und Risikobewertung

### Gesamtrisiko: **HOCH** 🔴

**Kritische Risiken:**
- API-Schlüssel-Exposition ermöglicht unbegrenzten Missbrauch
- Fehlende Authentifizierung auf teuren AI-APIs
- Keine Zugriffskontrollen auf Datenbankebene

**Geschätzter Aufwand für Remediation:**
- **Kritische Probleme:** 2-3 Entwicklertage
- **Hochgradige Probleme:** 3-5 Entwicklertage
- **Mittlere/Niedrige Probleme:** 5-7 Entwicklertage
- **Gesamt:** ~10-15 Entwicklertage

### Finanzielle Risiken:

**Ohne Fixes:**
- Unbegrenzte AI API-Kosten: **$X,XXX - $XX,XXX/Monat**
- Datenverstoß (DSGVO Strafen): **bis zu 4% des Jahresumsatzes**
- Reputationsschaden: **Unbezifferbar**

**Mit Fixes:**
- Kontrollierte API-Kosten
- Compliance-konform
- Vertrauen der Nutzer

### Erfolgsmetriken nach Remediation:

- [ ] 0 kritische Schwachstellen
- [ ] 0 hochgradige Schwachstellen
- [ ] NPM Audit: 0 moderate/high vulnerabilities
- [ ] OWASP Top 10: >80% Compliance
- [ ] Security Headers: A+ Rating (securityheaders.com)
- [ ] Penetration Test: Bestanden

---

## Anhang A: Code-Beispiele für sichere Implementierung

### A.1 Geschützter API-Route Template

```typescript
// lib/auth/verify-request.ts
import { createClient } from '@/lib/supabase/server'
import { NextRequest, NextResponse } from 'next/server'

export async function verifyAuthenticatedRequest(
  request: NextRequest
): Promise<
  | { success: true; userId: string }
  | { success: false; response: NextResponse }
> {
  const supabase = createClient()
  const { data: { user }, error } = await supabase.auth.getUser()

  if (error || !user) {
    return {
      success: false,
      response: NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      ),
    }
  }

  return { success: true, userId: user.id }
}

// Verwendung in API Route:
export async function POST(request: NextRequest) {
  const authResult = await verifyAuthenticatedRequest(request)
  if (!authResult.success) {
    return authResult.response
  }

  const userId = authResult.userId
  // ... Rest der Logik
}
```

### A.2 Input Validation Helper

```typescript
// lib/validation/schemas.ts
import { z } from 'zod'

export const chatMessageSchema = z.object({
  messages: z.array(
    z.object({
      role: z.enum(['user', 'assistant', 'system']),
      content: z.string().min(1).max(10000),
    })
  ).min(1).max(50),
})

export const imagePromptSchema = z.object({
  prompt: z.string().min(10).max(1000),
  negativePrompt: z.string().max(500).optional(),
})

export const audioUploadSchema = z.object({
  audio: z.string().refine(
    (val) => {
      try {
        const buffer = Buffer.from(val, 'base64')
        return buffer.length <= 25 * 1024 * 1024 // 25MB
      } catch {
        return false
      }
    },
    { message: 'Invalid base64 audio or file too large' }
  ),
})
```

---

## Anhang B: Nützliche Links und Ressourcen

### Security Standards:
- **OWASP Top 10:** https://owasp.org/www-project-top-ten/
- **CWE Top 25:** https://cwe.mitre.org/top25/
- **NIST Cybersecurity Framework:** https://www.nist.gov/cyberframework

### Next.js Security:
- **Next.js Security Headers:** https://nextjs.org/docs/advanced-features/security-headers
- **Vercel Security Best Practices:** https://vercel.com/docs/security/best-practices

### Supabase Security:
- **Row Level Security:** https://supabase.com/docs/guides/auth/row-level-security
- **Auth Best Practices:** https://supabase.com/docs/guides/auth/auth-helpers/nextjs

### Tools:
- **Security Headers Checker:** https://securityheaders.com/
- **SSL Labs:** https://www.ssllabs.com/ssltest/
- **Mozilla Observatory:** https://observatory.mozilla.org/

---

**Ende des Security Audit Reports**

**Erstellt am:** 26. Oktober 2025
**Nächstes Audit empfohlen:** Nach Implementierung der Fixes + alle 6 Monate
**Kontakt:** security@your-domain.com
