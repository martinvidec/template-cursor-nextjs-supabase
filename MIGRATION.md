# Migration von Firebase zu Supabase

Diese Dokumentation beschreibt die Migration des Templates von Firebase zu Supabase.

## Durchgeführte Änderungen

### 1. Abhängigkeiten
- **Entfernt**: `firebase` (^10.13.0)
- **Hinzugefügt**: `@supabase/supabase-js`

### 2. Konfiguration
- **Entfernt**: `src/lib/firebase/` Ordner
- **Hinzugefügt**: `src/lib/supabase/` Ordner mit:
  - `supabase.ts` - Supabase Client-Konfiguration
  - `supabaseUtils.ts` - Utility-Funktionen für Auth, Database und Storage

### 3. Authentifizierung
- **AuthContext**: Vollständig auf Supabase Auth umgestellt
- **OAuth Callback**: Neuer Handler in `src/app/auth/callback/route.ts`
- **Hooks**: `useAuth` Hook weiterhin kompatibel

### 4. Utility-Funktionen
Alle Firebase-Funktionen wurden durch Supabase-Äquivalente ersetzt:
- `addDocument()` - Hinzufügen von Dokumenten
- `getDocuments()` - Abrufen von Dokumenten
- `updateDocument()` - Aktualisieren von Dokumenten
- `deleteDocument()` - Löschen von Dokumenten
- `uploadFile()` - Datei-Upload
- `signInWithGoogle()` - Google OAuth
- `logoutUser()` - Benutzer abmelden

### 5. Komponenten
- **VoiceRecorder**: Import-Pfad von Firebase zu Supabase geändert
- **SignInWithGoogle**: Keine Änderungen erforderlich (nutzt AuthContext)

### 6. Konfigurationsdateien
- **next.config.mjs**: Firebase Storage Domain durch Supabase Domain ersetzt
- **.cursorrules**: Dokumentation aktualisiert
- **README.md**: Firebase-Referenzen durch Supabase ersetzt
- **paths/*.md**: Template-Dokumentationen aktualisiert

### 7. Umgebungsvariablen
Neue `.env.example` mit Supabase-Variablen:
```
NEXT_PUBLIC_SUPABASE_URL=your_supabase_project_url
NEXT_PUBLIC_SUPABASE_ANON_KEY=your_supabase_anon_key
```

## Setup für Entwickler

1. Supabase-Projekt erstellen auf [supabase.com](https://supabase.com)
2. `.env.local` erstellen mit echten Supabase-Credentials
3. Google OAuth in Supabase konfigurieren
4. Storage-Bucket "files" erstellen (falls File-Upload verwendet wird)

## Kompatibilität

Die API der Utility-Funktionen wurde beibehalten, sodass bestehender Code weiterhin funktioniert. Lediglich die Import-Pfade müssen von `../lib/firebase/firebaseUtils` zu `../lib/supabase/supabaseUtils` geändert werden. 