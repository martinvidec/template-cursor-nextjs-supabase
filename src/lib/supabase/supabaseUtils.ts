import { supabase } from './supabase'

// Auth functions
export const logoutUser = async () => {
  const { error } = await supabase.auth.signOut()
  if (error) {
    console.error('Error signing out:', error)
    throw error
  }
}

export const signInWithGoogle = async () => {
  const { data, error } = await supabase.auth.signInWithOAuth({
    provider: 'google',
    options: {
      redirectTo: `${window.location.origin}/auth/callback`
    }
  })
  
  if (error) {
    console.error('Error signing in with Google:', error)
    throw error
  }
  
  return data
}

// Database functions
export const addDocument = async (tableName: string, data: any) => {
  const { data: result, error } = await supabase
    .from(tableName)
    .insert(data)
    .select()
    .single()
  
  if (error) {
    console.error('Error adding document:', error)
    throw error
  }
  
  return result
}

export const getDocuments = async (tableName: string) => {
  const { data, error } = await supabase
    .from(tableName)
    .select('*')
  
  if (error) {
    console.error('Error getting documents:', error)
    throw error
  }
  
  return data || []
}

export const updateDocument = async (tableName: string, id: string, data: any) => {
  const { data: result, error } = await supabase
    .from(tableName)
    .update(data)
    .eq('id', id)
    .select()
    .single()
  
  if (error) {
    console.error('Error updating document:', error)
    throw error
  }
  
  return result
}

export const deleteDocument = async (tableName: string, id: string) => {
  const { error } = await supabase
    .from(tableName)
    .delete()
    .eq('id', id)
  
  if (error) {
    console.error('Error deleting document:', error)
    throw error
  }
}

// Storage functions
export const uploadFile = async (file: File, path: string) => {
  const { data, error } = await supabase.storage
    .from('files')
    .upload(path, file)
  
  if (error) {
    console.error('Error uploading file:', error)
    throw error
  }
  
  // Get public URL
  const { data: { publicUrl } } = supabase.storage
    .from('files')
    .getPublicUrl(path)
  
  return publicUrl
} 