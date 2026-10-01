import Tooltip from '@mui/material/Tooltip'
import type { ReactElement, ReactNode } from 'react'

/** MUI tooltip styled as a Level 3 flyout. Used for definitions, never for data the analyst needs to act. */
export function Hint({ title, children, placement = 'top' }: {
  title: ReactNode
  children: ReactElement
  placement?: 'top' | 'bottom' | 'left' | 'right'
}) {
  return (
    <Tooltip title={title} placement={placement} arrow={false} enterDelay={250} describeChild>
      {children}
    </Tooltip>
  )
}
