import '@fontsource-variable/inter'
import '@fontsource-variable/jetbrains-mono'
import './index.css'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import CssBaseline from '@mui/material/CssBaseline'
import { StyledEngineProvider, ThemeProvider } from '@mui/material/styles'
import App from './App'
import { muiTheme } from './theme/muiTheme'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <StyledEngineProvider enableCssLayer>
      <ThemeProvider theme={muiTheme}>
        <CssBaseline enableColorScheme />
        <App />
      </ThemeProvider>
    </StyledEngineProvider>
  </StrictMode>,
)
