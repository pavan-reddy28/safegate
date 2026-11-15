import { Capacitor, registerPlugin } from "@capacitor/core";
import { Browser } from "@capacitor/browser";

const ExternalBrowser = registerPlugin("ExternalBrowser");

export function isValidExternalHttpUrl(rawUrl) {
  try {
    const parsed = new URL(String(rawUrl || "").trim());
    return (
      (parsed.protocol === "http:" || parsed.protocol === "https:") &&
      Boolean(parsed.hostname) &&
      !parsed.username &&
      !parsed.password
    );
  } catch {
    return false;
  }
}

export async function openInExternalBrowser(targetUrl) {
  const url = String(targetUrl || "").trim();
  if (!isValidExternalHttpUrl(url)) {
    throw new Error("INVALID_EXTERNAL_URL");
  }

  if (Capacitor.isNativePlatform()) {
    try {
      return await ExternalBrowser.openExternal({ url });
    } catch {
      try {
        await Browser.open({
          url,
          toolbarColor: "#090b10"
        });
        return { opened: true, packageName: "custom-tab-fallback" };
      } catch {
        window.location.assign(url);
        return { opened: true, packageName: "webview-fallback" };
      }
    }
  }

  window.location.assign(url);
  return { opened: true, packageName: "web" };
}

export async function getNativeHardwareDeviceInfo() {
  if (!Capacitor.isNativePlatform()) {
    return null;
  }
  try {
    const info = await ExternalBrowser.getDeviceInfo();
    if (info && typeof info.deviceName === "string" && info.deviceName.trim()) {
      return {
        deviceName: info.deviceName.trim(),
        manufacturer: info.manufacturer || "",
        model: info.model || ""
      };
    }
  } catch {
    // Ignore native plugin fallback errors
  }
  return null;
}
