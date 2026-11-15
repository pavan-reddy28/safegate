export function LockerMark({ className = 'h-7 w-7' }) {
  return (
    <svg
      viewBox="0 0 64 64"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      aria-hidden="true"
    >
      <path
        d="M17 31H11.5C7.91 31 5 33.91 5 37.5C5 41.09 7.91 44 11.5 44H17"
        stroke="#38BDF8"
        strokeWidth="4.2"
        strokeLinecap="round"
      />
      <path
        d="M47 31H52.5C56.09 31 59 33.91 59 37.5C59 41.09 56.09 44 52.5 44H47"
        stroke="#38BDF8"
        strokeWidth="4.2"
        strokeLinecap="round"
      />
      <path
        d="M22.5 27V21.5C22.5 16.25 26.75 12 32 12C37.25 12 41.5 16.25 41.5 21.5V27"
        stroke="#10B981"
        strokeWidth="4.4"
        strokeLinecap="round"
      />
      <rect
        x="17"
        y="26.5"
        width="30"
        height="24.5"
        rx="7.5"
        fill="#10B981"
        fillOpacity="0.16"
        stroke="#10B981"
        strokeWidth="3.6"
      />
      <circle cx="32" cy="36.5" r="2.8" fill="#A7F3D0" />
      <path d="M32 39V43.5" stroke="#A7F3D0" strokeWidth="3.2" strokeLinecap="round" />
    </svg>
  );
}
