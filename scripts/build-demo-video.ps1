param(
  [string]$Ffmpeg = "ffmpeg"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$source = Join-Path $root "demo\vibeguard-demo.ass"
$output = Join-Path $root "media\vibeguard-demo.mp4"

& $Ffmpeg -y -hide_banner -loglevel error `
  -f lavfi -i "color=c=0x0d1117:s=1280x720:d=14:r=30" `
  -vf "drawbox=x=64:y=164:w=1152:h=468:color=0x161b22:t=fill,drawbox=x=64:y=164:w=1152:h=468:color=0x30363d:t=2,subtitles='$($source.Replace('\', '/').Replace(':', '\:'))'" `
  -c:v libx264 -pix_fmt yuv420p -movflags +faststart $output

if ($LASTEXITCODE -ne 0) {
  throw "ffmpeg failed to build the VibeGuard demo video."
}

Write-Output "Wrote $output"
