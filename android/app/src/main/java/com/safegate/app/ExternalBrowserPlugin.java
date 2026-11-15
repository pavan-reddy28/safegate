package com.safegate.app;

import android.content.ActivityNotFoundException;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.os.Build;
import android.text.TextUtils;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

@CapacitorPlugin(name = "ExternalBrowser")
public class ExternalBrowserPlugin extends Plugin {

    private static final List<String> PREFERRED_BROWSER_PACKAGES = Arrays.asList(
        "com.android.chrome",
        "com.chrome.beta",
        "com.chrome.dev",
        "com.chrome.canary",
        "com.brave.browser",
        "org.mozilla.firefox",
        "org.mozilla.fenix",
        "com.microsoft.emmx",
        "com.sec.android.app.sbrowser",
        "com.opera.browser",
        "com.opera.mini.native",
        "com.duckduckgo.mobile.android",
        "com.kiwibrowser.browser",
        "com.vivaldi.browser",
        "org.chromium.chrome"
    );

    @PluginMethod
    public void openExternal(PluginCall call) {
        String rawUrl = call.getString("url");
        if (TextUtils.isEmpty(rawUrl)) {
            call.reject("URL_REQUIRED");
            return;
        }

        final Uri uri;
        try {
            uri = Uri.parse(rawUrl.trim());
        } catch (Exception ex) {
            call.reject("INVALID_URL");
            return;
        }

        String scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase(Locale.US) : "";
        if ((!"http".equals(scheme) && !"https".equals(scheme)) || TextUtils.isEmpty(uri.getHost()) || uri.getUserInfo() != null) {
            call.reject("UNSUPPORTED_URL");
            return;
        }

        Context context = getContext();
        if (context == null) {
            call.reject("CONTEXT_UNAVAILABLE");
            return;
        }

        String selfPackage = context.getPackageName();
        PackageManager pm = context.getPackageManager();

        List<ResolveInfo> candidates = queryExternalBrowsers(pm, uri, selfPackage);
        ResolveInfo chosen = pickTargetBrowser(pm, candidates, selfPackage);

        try {
            if (chosen != null && chosen.activityInfo != null) {
                Intent browserIntent = new Intent(Intent.ACTION_VIEW, uri);
                browserIntent.addCategory(Intent.CATEGORY_BROWSABLE);
                browserIntent.setComponent(
                    new ComponentName(chosen.activityInfo.packageName, chosen.activityInfo.name)
                );
                browserIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
                context.startActivity(browserIntent);

                JSObject result = new JSObject();
                result.put("opened", true);
                result.put("packageName", chosen.activityInfo.packageName);
                call.resolve(result);
                return;
            }

            // Fallback: Android chooser excluding SafeGate itself so we never loop back or open Custom Tabs
            Intent fallbackIntent = new Intent(Intent.ACTION_VIEW, uri);
            fallbackIntent.addCategory(Intent.CATEGORY_BROWSABLE);

            Intent chooser = Intent.createChooser(fallbackIntent, "Open with browser");
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                chooser.putExtra(
                    Intent.EXTRA_EXCLUDE_COMPONENTS,
                    new ComponentName[] { new ComponentName(context, MainActivity.class) }
                );
            }
            chooser.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            context.startActivity(chooser);

            JSObject result = new JSObject();
            result.put("opened", true);
            result.put("packageName", "chooser");
            call.resolve(result);
        } catch (ActivityNotFoundException ex) {
            call.reject("NO_EXTERNAL_BROWSER_FOUND", ex);
        } catch (Exception ex) {
            call.reject("EXTERNAL_BROWSER_LAUNCH_FAILED", ex);
        }
    }

    private List<ResolveInfo> queryExternalBrowsers(PackageManager pm, Uri uri, String selfPackage) {
        Intent probeIntent = new Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com"));
        probeIntent.addCategory(Intent.CATEGORY_BROWSABLE);

        int flags = PackageManager.MATCH_ALL;
        List<ResolveInfo> results = pm.queryIntentActivities(probeIntent, flags);
        if (results == null || results.isEmpty()) {
            Intent specificIntent = new Intent(Intent.ACTION_VIEW, uri);
            specificIntent.addCategory(Intent.CATEGORY_BROWSABLE);
            results = pm.queryIntentActivities(specificIntent, flags);
        }

        List<ResolveInfo> filtered = new ArrayList<>();
        if (results == null) {
            return filtered;
        }

        for (ResolveInfo info : results) {
            if (info == null || info.activityInfo == null) {
                continue;
            }
            String pkg = info.activityInfo.packageName;
            if (TextUtils.isEmpty(pkg)) {
                continue;
            }
            if (pkg.equals(selfPackage) || "android".equals(pkg)) {
                continue;
            }
            if (!info.activityInfo.exported) {
                continue;
            }
            filtered.add(info);
        }
        return filtered;
    }

    private ResolveInfo pickTargetBrowser(PackageManager pm, List<ResolveInfo> candidates, String selfPackage) {
        if (candidates.isEmpty()) {
            return null;
        }

        // 1. Prefer Google Chrome & well-known standalone browsers first
        for (String preferredPkg : PREFERRED_BROWSER_PACKAGES) {
            for (ResolveInfo candidate : candidates) {
                if (preferredPkg.equals(candidate.activityInfo.packageName)) {
                    return candidate;
                }
            }
        }

        // 2. Otherwise check system default browser if it's not SafeGate or Android Resolver
        Intent defaultProbe = new Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com"));
        defaultProbe.addCategory(Intent.CATEGORY_BROWSABLE);
        ResolveInfo defaultInfo = pm.resolveActivity(defaultProbe, PackageManager.MATCH_DEFAULT_ONLY);
        if (defaultInfo != null && defaultInfo.activityInfo != null) {
            String defaultPkg = defaultInfo.activityInfo.packageName;
            if (!TextUtils.isEmpty(defaultPkg) && !defaultPkg.equals(selfPackage) && !"android".equals(defaultPkg)) {
                for (ResolveInfo candidate : candidates) {
                    if (defaultPkg.equals(candidate.activityInfo.packageName)) {
                        return candidate;
                    }
                }
            }
        }

        // 3. Fallback to first available external browser
        return candidates.get(0);
    }

    @PluginMethod
    public void getDeviceInfo(PluginCall call) {
        String manufacturer = safeText(Build.MANUFACTURER);
        String brand = safeText(Build.BRAND);
        String model = safeText(Build.MODEL);
        String marketName = readHardwareMarketName();

        String deviceName = buildCleanDeviceName(manufacturer, brand, model, marketName);

        JSObject result = new JSObject();
        result.put("deviceName", deviceName);
        result.put("manufacturer", manufacturer);
        result.put("model", model);
        call.resolve(result);
    }

    private String readHardwareMarketName() {
        String[] sysPropKeys = new String[] {
            "ro.vivo.market.name",
            "ro.product.marketname",
            "ro.oppo.market.name",
            "ro.config.marketing_name",
            "ro.vendor.oplus.market.name"
        };
        try {
            Class<?> spClass = Class.forName("android.os.SystemProperties");
            java.lang.reflect.Method getMethod = spClass.getMethod("get", String.class, String.class);
            for (String key : sysPropKeys) {
                Object raw = getMethod.invoke(null, key, "");
                String val = sanitizeHardwareLabel(raw != null ? String.valueOf(raw) : "");
                if (!TextUtils.isEmpty(val)) {
                    return val;
                }
            }
        } catch (Exception ignored) {
            // OEM market name sysprop not readable on this OS build; fall back to Build.MANUFACTURER + Build.MODEL
        }
        return "";
    }

    private String buildCleanDeviceName(String manufacturer, String brand, String model, String marketName) {
        String primaryVendor = !TextUtils.isEmpty(brand) ? brand : manufacturer;
        String cleanVendor = formatVendorName(primaryVendor);
        String cleanMarket = sanitizeHardwareLabel(marketName);
        String cleanModel = sanitizeHardwareLabel(model);

        String chosenModel = !TextUtils.isEmpty(cleanMarket) ? cleanMarket : cleanModel;
        if (TextUtils.isEmpty(chosenModel)) {
            return !TextUtils.isEmpty(cleanVendor) ? cleanVendor : "Android Device";
        }

        if (TextUtils.isEmpty(cleanVendor)) {
            return clampHardwareName(chosenModel);
        }

        String lowerModel = chosenModel.toLowerCase(Locale.US);
        String lowerVendor = cleanVendor.toLowerCase(Locale.US);
        if (lowerModel.startsWith(lowerVendor)) {
            return clampHardwareName(chosenModel);
        }

        return clampHardwareName(cleanVendor + " " + chosenModel);
    }

    private String formatVendorName(String rawVendor) {
        String cleaned = sanitizeHardwareLabel(rawVendor);
        if (TextUtils.isEmpty(cleaned)) {
            return "";
        }
        if ("samsung".equalsIgnoreCase(cleaned)) return "Samsung";
        if ("google".equalsIgnoreCase(cleaned)) return "Google";
        if ("vivo".equalsIgnoreCase(cleaned)) return "Vivo";
        if ("oneplus".equalsIgnoreCase(cleaned)) return "OnePlus";
        if ("xiaomi".equalsIgnoreCase(cleaned)) return "Xiaomi";
        if ("redmi".equalsIgnoreCase(cleaned)) return "Redmi";
        if ("poco".equalsIgnoreCase(cleaned)) return "POCO";
        if ("oppo".equalsIgnoreCase(cleaned)) return "OPPO";
        if ("realme".equalsIgnoreCase(cleaned)) return "realme";
        if ("motorola".equalsIgnoreCase(cleaned)) return "Motorola";
        return Character.toUpperCase(cleaned.charAt(0)) + cleaned.substring(1);
    }

    private String safeText(String raw) {
        return sanitizeHardwareLabel(raw);
    }

    private String sanitizeHardwareLabel(String raw) {
        if (raw == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if ((c >= 'A' && c <= 'Z') ||
                (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') ||
                c == ' ' || c == '-' || c == '_' || c == '.' || c == '+' || c == '(' || c == ')') {
                sb.append(c);
            }
        }
        return sb.toString().trim().replaceAll("\\s{2,}", " ");
    }

    private String clampHardwareName(String value) {
        if (TextUtils.isEmpty(value)) {
            return "Android Device";
        }
        return value.length() > 80 ? value.substring(0, 80).trim() : value;
    }
}
