import { createTheme } from '@mui/material/styles'

/**
 * MUI in the "black ice" look: permanent dark mode, pure black surfaces,
 * square corners, neon accent. Values mirror the tokens in index.css.
 */
const SANS = "'Chakra Petch', 'Bahnschrift', ui-sans-serif, system-ui, sans-serif"

export const muiTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: { main: '#00FF9C', contrastText: '#000000' },
    secondary: { main: '#B266FF' },
    error: { main: '#FF2E5B' },
    warning: { main: '#FFE600' },
    info: { main: '#00E5FF' },
    success: { main: '#00FF9C' },
    background: { default: '#000000', paper: '#0A0A0A' },
    text: { primary: '#E6E6E6', secondary: '#A3A3A3' },
    divider: '#242424',
  },
  shape: { borderRadius: 0 },
  typography: {
    fontFamily: SANS,
    fontSize: 13,
  },
  components: {
    MuiTooltip: {
      styleOverrides: {
        tooltip: {
          background: '#0A0A0A',
          border: '1px solid #4A4A4A',
          borderRadius: 0,
          boxShadow: '0px 6px 18px rgba(0, 0, 0, 0.8)',
          color: '#E6E6E6',
          fontFamily: SANS,
          fontSize: 12,
          lineHeight: '17px',
          padding: '6px 8px',
          maxWidth: 360,
        },
      },
    },
    MuiDrawer: {
      styleOverrides: {
        paper: { background: '#0A0A0A', borderLeft: '1px solid #00FF9C', backgroundImage: 'none', borderRadius: 0 },
      },
    },
    MuiBackdrop: { styleOverrides: { root: { backgroundColor: 'rgba(0, 0, 0, 0.75)' } } },
    MuiPaper: { styleOverrides: { root: { backgroundImage: 'none', borderRadius: 0 } } },
  },
})
