/**
 * Chapter 15 / N69, statically: the application code has no data of its own.
 *
 * - nothing outside src/test imports from src/test;
 * - no random numbers, no mock or faker libraries, no hard-coded sample data;
 * - every service module reaches the API through services/client.ts.
 *
 * Sources are read through Vite's import.meta.glob, so the check sees exactly
 * the files the bundler would.
 */
import { describe, expect, it } from 'vitest'

const all = import.meta.glob('../**/*.{ts,tsx}', { query: '?raw', import: 'default', eager: true }) as Record<string, string>
const app = Object.entries(all).filter(([p]) => !p.startsWith('../test/'))
const named = (pred: (p: string, src: string) => boolean) => app.filter(([p, s]) => pred(p, s)).map(([p]) => p)

describe('the application holds no data of its own', () => {
  it('finds the application files', () => {
    expect(app.length).toBeGreaterThan(40)
  })

  it('never imports from src/test', () => {
    expect(named((_, s) => /from\s+['"](@\/test|(\.\.?\/)+test)\//.test(s))).toEqual([])
  })

  it('makes no random numbers and uses no mock or faker library', () => {
    expect(named((_, s) => /Math\.random|faker|\bmsw\b|mockData|sampleData|dummyData/.test(s))).toEqual([])
  })

  it('reaches the API only through services/client.ts', () => {
    const services = app.filter(([p]) => p.startsWith('../services/') && !p.endsWith('/client.ts'))
    expect(services.length).toBeGreaterThan(8)
    for (const [p, s] of services) {
      expect(s, p).toMatch(/from '\.\/client'/)
      expect(s, p).not.toMatch(/\bfetch\(|new XMLHttpRequest/)
    }
    expect(named((p, s) => !p.startsWith('../services/') && /\bfetch\(|axios\.(get|post)\(/.test(s))).toEqual([])
  })
})
