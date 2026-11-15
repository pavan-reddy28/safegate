export function UrlLockerIcon({ variant = "ready", className = "h-12 w-12" }) {
  const palette = {
    ready: {
      shackle: "#34D399",
      bodyFill: "#0F172A",
      bodyStroke: "#34D399",
      link: "#38BDF8",
      keyhole: "#6EE7B7",
      unlocked: false
    },
    checking: {
      shackle: "#67E8F9",
      bodyFill: "#0F172A",
      bodyStroke: "#67E8F9",
      link: "#818CF8",
      keyhole: "#A5F3FC",
      unlocked: false
    },
    safe: {
      shackle: "#34D399",
      bodyFill: "#06291E",
      bodyStroke: "#34D399",
      link: "#22D3EE",
      keyhole: "#6EE7B7",
      unlocked: true
    },
    blocked: {
      shackle: "#FB7185",
      bodyFill: "#2A0B14",
      bodyStroke: "#F43F5E",
      link: "#FDA4AF",
      keyhole: "#FB7185",
      unlocked: false
    },
    suspicious: {
      shackle: "#FBBF24",
      bodyFill: "#261807",
      bodyStroke: "#F59E0B",
      link: "#FCD34D",
      keyhole: "#FDE68A",
      unlocked: false
    },
    hold: {
      shackle: "#38BDF8",
      bodyFill: "#0B1E2E",
      bodyStroke: "#38BDF8",
      link: "#7DD3FC",
      keyhole: "#BAE6FD",
      unlocked: false
    }
  }[variant] || {
    shackle: "#34D399",
    bodyFill: "#0F172A",
    bodyStroke: "#34D399",
    link: "#38BDF8",
    keyhole: "#6EE7B7",
    unlocked: false
  };

  return (
    <svg
      viewBox="0 0 64 64"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      aria-hidden="true"
    >
      {/* Left URL chain link */}
      <path
        d="M17 34H12C8.686 34 6 36.686 6 40C6 43.314 8.686 46 12 46H19"
        stroke={palette.link}
        strokeWidth="3.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {/* Right URL chain link */}
      <path
        d="M47 34H52C55.314 34 58 36.686 58 40C58 43.314 55.314 46 52 46H45"
        stroke={palette.link}
        strokeWidth="3.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />

      {/* Padlock shackle (lifts cleanly when safe/unlocked) */}
      {palette.unlocked ? (
        <path
          d="M23 26V17.5C23 12.253 27.029 8 32 8C36.62 8 40.427 11.676 40.94 16.4"
          stroke={palette.shackle}
          strokeWidth="4"
          strokeLinecap="round"
        />
      ) : (
        <path
          d="M23 27V19C23 14.029 27.029 10 32 10C36.971 10 41 14.029 41 19V27"
          stroke={palette.shackle}
          strokeWidth="4"
          strokeLinecap="round"
        />
      )}

      {/* Lock body */}
      <rect
        x="16"
        y="26"
        width="32"
        height="26"
        rx="7"
        fill={palette.bodyFill}
        stroke={palette.bodyStroke}
        strokeWidth="3"
      />

      {/* Precision keyhole + lower security bar */}
      <circle cx="32" cy="37" r="3.4" fill={palette.keyhole} />
      <path
        d="M32 39.5V45"
        stroke={palette.keyhole}
        strokeWidth="3.2"
        strokeLinecap="round"
      />
    </svg>
  );
}

export default UrlLockerIcon;
