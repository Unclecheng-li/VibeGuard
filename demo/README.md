# Demo Assets

`unsafe-ai-sample.ts` is deliberately unsafe and must never be executed or used as application code. Its API-key-like value is a non-functional placeholder chosen to exercise VibeGuard's redaction and hardcoded-secret detection.

The committed `media/vibeguard-demo.mp4` is a 14-second rendering of the actual VibeGuard CLI findings for that sample. Rebuild it from the repository root after changing the sample or subtitle source:

```powershell
.\scripts\build-demo-video.ps1 -Ffmpeg C:\ffmpeg\ffmpeg.exe
```

The `vibeguard-demo.ass` subtitle source intentionally mirrors the regression test in `tests/demoSample.test.ts`.
