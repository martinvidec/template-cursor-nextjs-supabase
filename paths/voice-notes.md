# Voice Notes App

Create a voice-based note-taking application with real-time transcription capabilities.

## Flow

1. User clicks "Start Recording" button
2. The app requests microphone permission
3. Audio is captured and sent to Deepgram API for real-time transcription
4. The transcribed text appears in real-time as the user speaks
5. User clicks "Stop Recording" to end the session
6. The final transcription is displayed
7. User can optionally edit the transcription
8. The note is saved with timestamp and transcription
9. User can view all their saved voice notes in a list
10. User can search through their notes
11. User can delete notes they no longer need

## Additional Features

- Real-time audio visualization during recording
- Ability to play back the original audio recording
- Export notes as text files
- Categorize notes with tags
- After there is done recording, the note is automatically saved with the date, time, and the transcription of the voice note into the Supabase database.

## Implementation Notes

This application is set-up with existing configuration for Deepgram APIs and Supabase. Implement all the functionality in the flow above while using the existing codebase as a starting point, but fully modify the codebase to fit the flow and functionality described above.
