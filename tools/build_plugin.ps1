# Windows build of usb_audio360.xex, equivalent to tools/build_plugin.sh but
# without Wine. Uses the installed Xbox 360 XDK 21256 ($env:XEDK) for
# cl/link/imagexex, headers and libraries, and XexTool from RXDK-360
# ($env:RXDK360) for the post-build flag check.
#
#   powershell -ExecutionPolicy Bypass -File tools\build_plugin.ps1 [-DebugApi]

param(
  [switch]$DebugApi,
  [string]$Xdk = $env:XEDK,
  [string]$XexTool = $(if ($env:XEXTOOL) { $env:XEXTOOL } elseif ($env:RXDK360) { Join-Path $env:RXDK360 'modern\bin\XexTool.exe' } else { '' })
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$src = Join-Path $root 'src'
$debugFlag = if ($DebugApi) { 1 } else { 0 }
$outDir = if ($DebugApi) { Join-Path $root 'bin\debug' } else { Join-Path $root 'bin' }
$build = Join-Path $root 'build\win'

foreach ($p in @("$Xdk\bin\win32\cl.exe", "$Xdk\include\xbox\xtl.h", "$Xdk\lib\xbox\xboxkrnl.lib", $XexTool)) {
  if (-not $p -or -not (Test-Path $p)) { throw "missing build input: $p" }
}

New-Item -ItemType Directory -Force $build, "$build\tmp", $outDir | Out-Null
Get-ChildItem $build -File | Where-Object { $_.Extension -in '.obj', '.pe', '.xex', '.map', '.txt' } | Remove-Item -Force
$env:TMP = "$build\tmp"; $env:TEMP = "$build\tmp"

$sources = 'driver', 'audio', 'settings', 'settings_ini', 'guide_ui', 'remote_volume',
           'diagnostics', 'xbox_usb_transport', 'uac_descriptors', 'uac_clock', 'detour'

foreach ($s in $sources) {
  & "$Xdk\bin\win32\cl.exe" /nologo /c /O2 /GS- /D_XBOX /DNDEBUG "/DUSB_AUDIO360_DEBUG_API=$debugFlag" `
    "/I$src" "/I$Xdk\include\xbox" "/I$Xdk\TechPreview\Jul12Compiler\include\xbox" `
    "/Fo$build\$s.obj" "$src\$s.cpp"
  if ($LASTEXITCODE) { throw "cl failed on $s.cpp" }
}

$objs = $sources | ForEach-Object { "$build\$_.obj" }
& "$Xdk\bin\win32\link.exe" /nologo /dll /release /xex:no "/libpath:$Xdk\lib\xbox" `
  "/map:$build\usb_audio360.map" "/out:$build\usb_audio360.pe" @objs xapilib.lib xboxkrnl.lib libcMT.lib
if ($LASTEXITCODE) { throw 'link failed' }

& "$Xdk\bin\win32\imagexex.exe" "/IN:$build\usb_audio360.pe" "/OUT:$build\usb_audio360.xex" "/CONFIG:$src\xex.xml"
if ($LASTEXITCODE) { throw 'imagexex failed' }

$info = & $XexTool -l "$build\usb_audio360.xex" 2>&1 | Out-String
$info | Set-Content -Encoding utf8 "$build\xextool-info.txt"
foreach ($flag in 'Devkit', 'Compressed', 'System Flash', 'DLL Module') {
  if ($info -notmatch "(?m)^  $flag\s*$") { throw "xex is missing expected flag '$flag' (see $build\xextool-info.txt)" }
}

Copy-Item "$build\usb_audio360.xex" "$outDir\usb_audio360.xex" -Force
if ($DebugApi) {
  python "$PSScriptRoot\debug_manifest.py" "$build\usb_audio360.map" "$build\usb_audio360.pe" "$outDir\usb_audio360.json"
}
$hash = (Get-FileHash "$outDir\usb_audio360.xex" -Algorithm SHA256).Hash.ToLower()
"$hash  $outDir\usb_audio360.xex"
"built $outDir\usb_audio360.xex"
