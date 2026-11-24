// Minimal line icons (24px grid, 1.6 stroke). Decorative by default (aria-hidden).
import type { SVGProps } from 'react'

type P = SVGProps<SVGSVGElement> & { size?: number }
function Svg({ size = 20, children, ...rest }: P & { children: React.ReactNode }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6}
      strokeLinecap="round" strokeLinejoin="round" aria-hidden focusable="false" {...rest}>{children}</svg>
  )
}

export const IHome = (p: P) => <Svg {...p}><path d="M4 11 12 4l8 7" /><path d="M6 10v9h12v-9" /></Svg>
export const IFolder = (p: P) => <Svg {...p}><path d="M3.5 6.5h6l2 2h9v10h-17z" /></Svg>
export const IPlus = (p: P) => <Svg {...p}><path d="M12 5v14M5 12h14" /></Svg>
export const IResults = (p: P) => <Svg {...p}><path d="M5 19V9M12 19V5M19 19v-7" /></Svg>
export const IShield = (p: P) => <Svg {...p}><path d="M12 3.5 5 6.5v5c0 4.4 3 7.7 7 9 4-1.3 7-4.6 7-9v-5z" /></Svg>
export const ISettings = (p: P) => <Svg {...p}><circle cx="12" cy="12" r="3" /><path d="M12 3v2.5M12 18.5V21M3 12h2.5M18.5 12H21M5.6 5.6l1.8 1.8M16.6 16.6l1.8 1.8M5.6 18.4l1.8-1.8M16.6 7.4l1.8-1.8" /></Svg>
export const ILogout = (p: P) => <Svg {...p}><path d="M14 4h5v16h-5M10 8l-4 4 4 4M6 12h10" /></Svg>
export const IMenu = (p: P) => <Svg {...p}><path d="M4 7h16M4 12h16M4 17h16" /></Svg>
export const IClose = (p: P) => <Svg {...p}><path d="M6 6l12 12M18 6 6 18" /></Svg>
export const ICheck = (p: P) => <Svg {...p}><path d="m5 12.5 4.5 4.5L19 7.5" /></Svg>
export const IAlert = (p: P) => <Svg {...p}><path d="M12 4 2.8 19.5h18.4z" /><path d="M12 10v4.5M12 17.2v.3" /></Svg>
export const IInfo = (p: P) => <Svg {...p}><circle cx="12" cy="12" r="8.5" /><path d="M12 11v5.5M12 7.8v.3" /></Svg>
export const IGlobe = (p: P) => <Svg {...p}><circle cx="12" cy="12" r="8.5" /><path d="M3.5 12h17M12 3.5c2.6 2.6 2.6 14.4 0 17M12 3.5c-2.6 2.6-2.6 14.4 0 17" /></Svg>
export const ICode = (p: P) => <Svg {...p}><path d="m9 8-4 4 4 4M15 8l4 4-4 4" /></Svg>
export const IApi = (p: P) => <Svg {...p}><path d="M7 7h10v10H7z" /><path d="M10 4v3M14 4v3M10 17v3M14 17v3M4 10h3M4 14h3M17 10h3M17 14h3" /></Svg>
export const IServer = (p: P) => <Svg {...p}><rect x="4" y="4.5" width="16" height="6" rx="1" /><rect x="4" y="13.5" width="16" height="6" rx="1" /><path d="M8 7.5h.01M8 16.5h.01" /></Svg>
export const ISun = (p: P) => <Svg {...p}><circle cx="12" cy="12" r="4" /><path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4" /></Svg>
export const IMoon = (p: P) => <Svg {...p}><path d="M19.5 14.5A8 8 0 0 1 9.5 4.5a8 8 0 1 0 10 10z" /></Svg>
export const IDownload = (p: P) => <Svg {...p}><path d="M12 4v11M7.5 10.5 12 15l4.5-4.5M5 19.5h14" /></Svg>
export const IStop = (p: P) => <Svg {...p}><rect x="6.5" y="6.5" width="11" height="11" rx="1" /></Svg>
export const IArrowLeft = (p: P) => <Svg {...p}><path d="M19 12H5M11 6l-6 6 6 6" /></Svg>

export function Logo({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden focusable="false">
      <path d="M16 3.5 5.5 7.6v7.6c0 6.4 4.4 11.3 10.5 13.3 6.1-2 10.5-6.9 10.5-13.3V7.6z" fill="#287C75" />
      <path d="M10.5 16.2 14.3 20l7.2-7.6" fill="none" stroke="#F3F4EF" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}
