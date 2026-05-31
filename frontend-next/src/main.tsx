import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App.tsx'
import './index.css'
import { getStoredTheme, applyTheme } from './lib/themes.ts'

// Apply stored theme synchronously before first render to avoid a flash.
applyTheme(getStoredTheme())

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter basename="/next">
      <App />
    </BrowserRouter>
  </StrictMode>,
)
