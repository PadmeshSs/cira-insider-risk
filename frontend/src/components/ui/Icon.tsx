import type { SVGProps } from 'react'

/** A small stroke icon set drawn for this console; 16px grid, 1.5px strokes. */
const PATHS = {
  overview: 'M2.5 13.5h11M4 11V7.5M7 11V4.5M10 11V6M13 11V2.5',
  alerts: 'M8 2.5 1.75 13.5h12.5L8 2.5ZM8 6.5v3.25M8 11.6v.15',
  users: 'M5.75 7.25a2.25 2.25 0 1 0 0-4.5 2.25 2.25 0 0 0 0 4.5ZM1.75 13.25c.4-2.3 2-3.5 4-3.5s3.6 1.2 4 3.5M10.5 3a2.1 2.1 0 0 1 0 4M12 9.9c1.3.5 2 1.6 2.25 3.35',
  system: 'M2.5 3.5h11v7h-11zM6 13.5h4M8 10.5v3M4.5 7l1.5-1.5 1.5 1.5 2-2.5L12 7',
  logout: 'M6 2.5H3v11h3M10.5 5 13.5 8l-3 3M13.5 8H6',
  search: 'M7 12a5 5 0 1 0 0-10 5 5 0 0 0 0 10ZM10.75 10.75 14 14',
  chevronRight: 'M6 3.5 10.5 8 6 12.5',
  chevronLeft: 'M10 3.5 5.5 8 10 12.5',
  chevronDown: 'M3.5 6 8 10.5 12.5 6',
  external: 'M9.5 2.5h4v4M13.5 2.5 7.5 8.5M11.5 9.5v4h-9v-9h4',
  info: 'M8 14.25a6.25 6.25 0 1 0 0-12.5 6.25 6.25 0 0 0 0 12.5ZM8 7.25v4M8 4.9v.1',
  warn: 'M8 1.75 1.5 13.75h13L8 1.75ZM8 6.25v3.5M8 11.6v.15',
  check: 'M3 8.5 6.5 12 13 4.5',
  x: 'M4 4l8 8M12 4l-8 8',
  refresh: 'M13.25 8a5.25 5.25 0 1 1-1.54-3.71M13.5 2.5v3h-3',
  user: 'M8 7.5a2.75 2.75 0 1 0 0-5.5 2.75 2.75 0 0 0 0 5.5ZM2.75 14c.5-2.75 2.5-4.25 5.25-4.25S12.75 11.25 13.25 14',
  history: 'M2 8a6 6 0 1 0 1.76-4.24M2 2.75V5.5h2.75M8 5v3.25l2.25 1.5',
  layers: 'M8 2 1.75 5.25 8 8.5l6.25-3.25L8 2ZM1.75 8.25 8 11.5l6.25-3.25M1.75 11.25 8 14.5l6.25-3.25',
  target: 'M8 14a6 6 0 1 0 0-12 6 6 0 0 0 0 12ZM8 11a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM8 8.01V8',
  play: 'M5 3v10l8-5-8-5Z',
  link: 'M6.5 9.5l3-3M7 4.5l1-1a2.8 2.8 0 0 1 4 4l-1 1M9 11.5l-1 1a2.8 2.8 0 0 1-4-4l1-1',
  calendar: 'M2.5 4h11v9.5h-11zM2.5 7h11M5.5 2.5v3M10.5 2.5v3',
  shield: 'M8 1.75 2.75 3.75v4c0 3.1 2.2 5.4 5.25 6.5 3.05-1.1 5.25-3.4 5.25-6.5v-4L8 1.75Z',
} as const

export type IconName = keyof typeof PATHS

export function Icon({ name, size = 16, ...rest }: { name: IconName; size?: number } & SVGProps<SVGSVGElement>) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      {...rest}
    >
      <path d={PATHS[name]} />
    </svg>
  )
}
