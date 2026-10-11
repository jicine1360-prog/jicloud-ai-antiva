# JICloud AI Antiva for Android

The current Android build is a selected-file hash viewer prototype. It computes
SHA-256 and gives extension-based warnings without deserializing or executing a
selected file. It does not validate model structures, identify malware, monitor
the device, or communicate with the Antiva guard. Full device monitoring would
require explicit Android capabilities and is a separate future phase.

## Build

```bash
./gradlew assembleDebug
```

The APK is written to `app/build/outputs/apk/debug/app-debug.apk`.
