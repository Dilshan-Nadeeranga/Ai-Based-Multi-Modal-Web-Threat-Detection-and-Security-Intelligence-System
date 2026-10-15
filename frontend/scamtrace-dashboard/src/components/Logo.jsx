import logoUrl from '../assets/scamtrace-logo.png'

// The logo image has a white background: blend it on light pages, frame it on dark ones.
export default function Logo({ className = 'h-9', onDark = false }) {
  const image = (
    <img
      src={logoUrl}
      alt="ScamTrace"
      width={535}
      height={144}
      className={`w-auto ${onDark ? '' : 'mix-blend-multiply'} ${className}`}
    />
  )

  if (!onDark) return image
  return <span className="inline-flex items-center rounded-md bg-white px-2 py-1">{image}</span>
}
