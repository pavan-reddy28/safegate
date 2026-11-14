
import React, { useCallback, useEffect, useRef, useState } from "react";
import { Capacitor } from "@capacitor/core";
import { App as CapacitorApp } from "@capacitor/app";
import { Browser } from "@capacitor/browser";
import { verifyDestination } from "./security/verificationService";
import "./App.css";

const isNative = Capacitor.isNativePlatform();

const DEMO_SAFE_URL = "https://example.com/";
const DEMO_PHISHING_URL =
  "https://testsafebrowsing.appspot.com/s/phishing.html";

function createRequestId() {
  const randomPart = globalThis.crypto?.randomUUID?.()
    ?.replaceAll("-", "")
    .slice(0, 8);

  return `SG-${Date.now().toString(36).toUpperCase()}-${(
    randomPart || Math.random().toString(36).slice(2, 10)
  ).toUpperCase()}`;
}

function getRequestId(result, fallback) {
  const candidates = [
    result?.requestId,
    result?.request_id,
    result?.meta?.requestId,
    result?.metadata?.requestId,
    result?.result?.requestId,
    result?.relay?.requestId,
    result?.google?.requestId,
  ];

  return (
    candidates.find(
      (value) => typeof value === "string" && value.trim().length > 0
    ) || fallback
  );
}


function classifyResult(result) {
  const finalDecision = String(
    result?.finalDecision || result?.decision || ""
  ).toUpperCase();

  // Only an explicit BLOCK decision means blocked.
  if (
    finalDecision === "BLOCK" ||
    finalDecision === "BLOCKED" ||
    result?.googleVerification?.status === "THREAT_FOUND"
  ) {
    return "blocked";
  }

  if (finalDecision === "SUSPICIOUS") {
    return "suspicious";
  }

  // HOLD must never be displayed as a confirmed threat.
  if (
    finalDecision === "HOLD" ||
    finalDecision === "ERROR" ||
    result?.verificationStatus === "INCOMPLETE"
  ) {
    return "hold";
  }

  if (
    finalDecision === "SAFE" ||
    finalDecision === "ALLOW" ||
    finalDecision === "NO_KNOWN_THREAT"
  ) {
    return "safe";
  }

  // Unknown decisions must fail closed.
  return "hold";
}


function validateHttpUrl(rawUrl) {
  try {
    const parsed = new URL(rawUrl);

    return (
      ["http:", "https:"].includes(parsed.protocol) &&
      !parsed.username &&
      !parsed.password
    );
  } catch {
    return false;
  }
}

function ShieldIcon({ size = 58 }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    >
      <path
        d="M12 2.5L20 5.5V11.2C20 16.2 16.6 20.2 12 21.5C7.4 20.2 4 16.2 4 11.2V5.5L12 2.5Z"
        stroke="currentColor"
        strokeWidth="1.55"
        strokeLinejoin="round"
      />
      <path
        d="M8.5 12L10.8 14.3L15.8 9.3"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function CopyIcon() {
  return (
    <svg
      width="15"
      height="15"
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <rect
        x="8"
        y="8"
        width="12"
        height="12"
        rx="2"
        stroke="currentColor"
        strokeWidth="1.7"
      />
      <path
        d="M16 8V5.8C16 4.8 15.2 4 14.2 4H5.8C4.8 4 4 4.8 4 5.8V14.2C4 15.2 4.8 16 5.8 16H8"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinecap="round"
      />
    </svg>
  );
}

function RequestIdCard({ value }) {
  const [copied, setCopied] = useState(false);

  const copyRequestId = async () => {
    if (!value) return;

    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  };

  if (!value) return null;

  return (
    <div className="request-id-card">
      <div className="request-id-info">
        <span className="request-id-label">REQUEST ID</span>
        <span className="request-id-value">{value}</span>
      </div>

      <button
        type="button"
        className="request-id-copy"
        onClick={copyRequestId}
        aria-label="Copy request ID"
        title="Copy request ID"
      >
        {copied ? (
          <span className="copied-label">COPIED</span>
        ) : (
          <CopyIcon />
        )}
      </button>
    </div>
  );
}

function HeroVisual() {
  return (
    <div className="hero-visual" aria-hidden="true">
      <div className="hero-orbit hero-orbit-one" />
      <div className="hero-orbit hero-orbit-two" />
      <div className="hero-orbit hero-orbit-three" />

      <div className="hero-particle particle-one" />
      <div className="hero-particle particle-two" />
      <div className="hero-particle particle-three" />

      <div className="hero-shield">
        <div className="hero-shield-glow" />
        <ShieldIcon size={66} />
      </div>
    </div>
  );
}

function CheckingVisual() {
  return (
    <div className="checking-visual" aria-hidden="true">
      <div className="checking-ring checking-ring-one" />
      <div className="checking-ring checking-ring-two" />
      <div className="checking-ring checking-ring-three" />

      <div className="checking-crosshair crosshair-horizontal" />
      <div className="checking-crosshair crosshair-vertical" />

      <div className="checking-scan-beam" />

      <div className="checking-core">
        <ShieldIcon size={58} />
      </div>

      <div className="checking-pulse pulse-one" />
      <div className="checking-pulse pulse-two" />
    </div>
  );
}

function ResultVisual({ type }) {
  return (
    <div className={`result-visual result-visual-${type}`}>
      <div className="result-visual-ring ring-one" />
      <div className="result-visual-ring ring-two" />
      <div className="result-visual-glow" />
      <div className="result-visual-icon">
        <ShieldIcon size={60} />
      </div>
    </div>
  );
}

function App() {
  const [phase, setPhase] = useState("ready");
  const [requestId, setRequestId] = useState("");
  const [isBusy, setIsBusy] = useState(false);

  const destinationRef = useRef("");
  const processingRef = useRef(false);
  const lastUrlRef = useRef("");
  const lastReceivedAtRef = useRef(0);
  const handoffRef = useRef(false);
  const mountedRef = useRef(true);

  const openDestination = useCallback(async () => {
    const url = destinationRef.current;

    if (!url || !validateHttpUrl(url)) {
      setPhase("invalid");
      return;
    }

    try {
      if (isNative) {
        await Browser.open({
          url,
          toolbarColor: "#080808",
        });
      } else {
        window.open(url, "_blank", "noopener,noreferrer");
      }
    } catch {
      if (mountedRef.current) {
        setPhase("hold");
      }
    }
  }, []);

  const handleIncomingUrl = useCallback(async (rawUrl) => {
    const url = String(rawUrl || "").trim();

    if (!url || processingRef.current) return;

    const now = Date.now();

    // Avoid processing duplicate Android launch and runtime events.
    if (
      url === lastUrlRef.current &&
      now - lastReceivedAtRef.current < 1500
    ) {
      return;
    }

    lastUrlRef.current = url;
    lastReceivedAtRef.current = now;

    const localRequestId = createRequestId();

    destinationRef.current = url;
    handoffRef.current = false;

    setRequestId(localRequestId);

    if (!validateHttpUrl(url)) {
      setPhase("invalid");
      return;
    }

    processingRef.current = true;
    setIsBusy(true);
    setPhase("checking");

    try {
      const result = await verifyDestination(url);

      if (!mountedRef.current) return;

      setRequestId(getRequestId(result, localRequestId));

      const outcome = classifyResult(result);
      setPhase(outcome);

      // Native Android: automatically hand off only an allowed link.
      if (outcome === "safe" && isNative && !handoffRef.current) {
        handoffRef.current = true;
        setPhase("opening");

        await new Promise((resolve) => window.setTimeout(resolve, 650));

        if (!mountedRef.current) return;

        try {
          await Browser.open({
            url,
            toolbarColor: "#080808",
          });

          if (mountedRef.current) {
            setPhase("safe");
          }
        } catch {
          if (mountedRef.current) {
            setPhase("hold");
          }
        }
      }
    } catch {
      if (mountedRef.current) {
        setPhase("hold");
      }
    } finally {
      processingRef.current = false;

      if (mountedRef.current) {
        setIsBusy(false);
      }
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;

    const handleWindowEvent = (event) => {
      const detail = event?.detail;

      const url =
        typeof detail === "string"
          ? detail
          : detail?.url || detail?.data?.url;

      if (url) handleIncomingUrl(url);
    };

    window.addEventListener(
      "safegate:incoming-url",
      handleWindowEvent
    );

    let appUrlListener;

    if (isNative) {
      CapacitorApp.addListener("appUrlOpen", (event) => {
        if (event?.url) {
          handleIncomingUrl(event.url);
        }
      }).then((listener) => {
        appUrlListener = listener;

        if (!mountedRef.current) {
          listener.remove();
        }
      });

      CapacitorApp.getLaunchUrl()
        .then((launch) => {
          if (launch?.url && mountedRef.current) {
            handleIncomingUrl(launch.url);
          }
        })
        .catch(() => {
          // No launch URL is a normal app startup.
        });
    }

    return () => {
      mountedRef.current = false;

      window.removeEventListener(
        "safegate:incoming-url",
        handleWindowEvent
      );

      appUrlListener?.remove();
    };
  }, [handleIncomingUrl]);

  const resetScreen = () => {
    if (processingRef.current) return;

    destinationRef.current = "";
    handoffRef.current = false;
    setRequestId("");
    setPhase("ready");
  };

  const runDemo = (url) => {
    handleIncomingUrl(url);
  };

  const renderContent = () => {
    if (phase === "ready") {
      return (
        <div className="ready-screen screen-enter">
          <HeroVisual />

          <div className="hero-copy">
            <span className="eyebrow"> </span>
            <h1>
              SafeGate<span className="title-period">.</span>
            </h1>
          </div>

          {!isNative && (
            <div className="demo-actions">
              <button
                type="button"
                className="primary-button"
                disabled={isBusy}
                onClick={() => runDemo(DEMO_SAFE_URL)}
              >
                <span>TEST SAFE LINK</span>
                <span className="button-arrow">↗</span>
              </button>

              <button
                type="button"
                className="danger-button"
                disabled={isBusy}
                onClick={() => runDemo(DEMO_PHISHING_URL)}
              >
                <span>TEST PHISHING BLOCK</span>
                <span className="button-arrow">↗</span>
              </button>
            </div>
          )}
        </div>
      );
    }

    if (phase === "checking" || phase === "opening") {
      return (
        <div className="state-screen screen-enter" aria-live="polite">
          <CheckingVisual />

          <div className="state-copy">
            <span className="state-kicker">
              {phase === "opening" ? "ALMOST THERE" : "PLEASE WAIT"}
            </span>

            <h1>
              {phase === "opening" ? "Opening link" : "Checking link"}
              <span className="animated-ellipsis">...</span>
            </h1>
          </div>

          <RequestIdCard value={requestId} />
        </div>
      );
    }

    const resultContent = {
      safe: {
        kicker: "VERIFIED",
        title: "You're good to go",
        description: "This link is ready to open.",
        button: isNative ? null : "OPEN LINK",
        visual: "safe",
      },
      blocked: {
        kicker: "BLOCKED",
        title: "Link blocked",
        description: "This link has been blocked for your protection.",
        button: "DONE",
        visual: "blocked",
      },
      suspicious: {
        kicker: "CAUTION",
        title: "Proceed with caution",
        description: "This link may carry a risk.",
        button: "GO BACK",
        visual: "suspicious",
      },
      hold: {
        kicker: "NOT VERIFIED",
        title: "Couldn't verify this link",
        description: "This link hasn't been opened.",
        button: "DONE",
        visual: "hold",
      },
      invalid: {
        kicker: "INVALID",
        title: "Invalid link",
        description: "This link cannot be opened.",
        button: "DONE",
        visual: "blocked",
      },
    };

    const content = resultContent[phase];

    if (!content) return null;

    return (
      <div
        className={`state-screen result-screen screen-enter result-${phase}`}
        aria-live="polite"
      >
        <ResultVisual type={content.visual} />

        <div className="state-copy">
          <span className="state-kicker">{content.kicker}</span>
          <h1>{content.title}</h1>
          <p>{content.description}</p>
        </div>

        <RequestIdCard value={requestId} />

        <div className="result-actions">
          {phase === "suspicious" ? (
            <>
              <button
                type="button"
                className="secondary-button"
                onClick={resetScreen}
              >
                GO BACK
              </button>

              <button
                type="button"
                className="danger-button"
                onClick={openDestination}
              >
                CONTINUE ANYWAY
              </button>
            </>
          ) : phase === "safe" ? (
            <>
              {!isNative && (
                <button
                  type="button"
                  className="primary-button"
                  onClick={openDestination}
                >
                  OPEN LINK <span className="button-arrow">↗</span>
                </button>
              )}

              <button
                type="button"
                className="secondary-button"
                onClick={resetScreen}
              >
                DONE
              </button>
            </>
          ) : (
            <button
              type="button"
              className="secondary-button"
              onClick={resetScreen}
            >
              DONE
            </button>
          )}
        </div>
      </div>
    );
  };

  return (
    <div className="safegate-app">
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />
      <div className="background-grid" />

      <header className="app-header">
        <div className="brand-mark">
          <span className="brand-symbol">
            <ShieldIcon size={23} />
          </span>
          <span className="brand-name">SAFEGATE</span>
        </div>

        <div className="status-pill">
          <span className="status-dot" />
          <span>{isNative ? "ACTIVE" : "PREVIEW"}</span>
        </div>
      </header>

      <main className="dashboard">
        <section className="main-card">
          <div className="card-top-line" />
          {renderContent()}
        </section>
      </main>

      <div className="bottom-decoration" aria-hidden="true">
        <span />
        <span />
        <span />
      </div>
    </div>
  );
}

export default App;
