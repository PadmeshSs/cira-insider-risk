import { createTheme } from '@mui/material/styles'

/**
 * MUI follows DESIGN.md: permanent dark mode, Level 3 flyouts with a 1px
 * border and the tactical shadow, 4px radius on sub-components.
 */
export const muiTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: { main: '#38BDF8', contrastText: '#0B0F17' },
    secondary: { main: '#818CF8' },
    error: { main: '#EF4444' },
    warning: { main: '#F59E0B' },
    background: { default: '#0B0F17', paper: '#151B28' },
    text: { primary: '#E2E8F0', secondary: '#94A3B8' },
    divider: '#222B38',
  },
  shape: { borderRadius: 4 },
  typography: {
    fontFamily: "'Inter Variable', 'Inter', ui-sans-serif, system-ui, sans-serif",
    fontSize: 13,
  },
  components: {
    MuiTooltip: {
      styleOverrides: {
        tooltip: {
          background: '#252E42',
          border: '1px solid #3B475D',
          boxShadow: '0px 4px 12px rgba(0, 0, 0, 0.6)',
          color: '#E2E8F0',
          fontSize: 12,
          lineHeight: '17px',
          padding: '6px 8px',
          maxWidth: 360,
        },
      },
    },
    MuiDrawer: {
      styleOverrides: {
        paper: { background: '#151B28', borderLeft: '1px solid #3B475D', backgroundImage: 'none' },
      },
    },
    MuiBackdrop: { styleOverrides: { root: { backgroundColor: 'rgba(5, 8, 13, 0.6)' } } },
    MuiPaper: { styleOverrides: { root: { backgroundImage: 'none' } } },
  },
})
