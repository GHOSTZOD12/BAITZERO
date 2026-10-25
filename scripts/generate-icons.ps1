Add-Type -AssemblyName System.Drawing

$src = "C:\Dev\LinkProtection\public\logo.png"
if (-not (Test-Path $src)) {
    Write-Error "Source logo.png not found at $src"
    exit 1
}

$img = [System.Drawing.Image]::FromFile($src)

function Resize-And-Save($width, $height, $destPath) {
    $target = New-Object System.Drawing.Bitmap $width, $height
    $g = [System.Drawing.Graphics]::FromImage($target)
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.Clear([System.Drawing.Color]::Transparent)
    $g.DrawImage($img, 0, 0, $width, $height)
    
    $parent = [System.IO.Path]::GetDirectoryName($destPath)
    if (-not (Test-Path $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    
    $target.Save($destPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose()
    $target.Dispose()
    Write-Host "Generated: $destPath ($width x $height)"
}

function Generate-Wide-Tile($canvasW, $canvasH, $logoSize, $destPath) {
    $target = New-Object System.Drawing.Bitmap $canvasW, $canvasH
    $g = [System.Drawing.Graphics]::FromImage($target)
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.Clear([System.Drawing.Color]::FromArgb(255, 5, 4, 8)) # BaitZero dark background
    
    $x = ($canvasW - $logoSize) / 2
    $y = ($canvasH - $logoSize) / 2
    $g.DrawImage($img, $x, $y, $logoSize, $logoSize)
    
    $parent = [System.IO.Path]::GetDirectoryName($destPath)
    if (-not (Test-Path $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    
    $target.Save($destPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose()
    $target.Dispose()
    Write-Host "Generated WideTile: $destPath ($canvasW x $canvasH)"
}

# 1. Tauri icons
$tauriDir = "C:\Dev\LinkProtection\src-tauri\icons"
if (Test-Path $tauriDir) {
    Resize-And-Save 16 16 "$tauriDir\16x16.png"
    Resize-And-Save 32 32 "$tauriDir\32x32.png"
    Resize-And-Save 64 64 "$tauriDir\64x64.png"
    Resize-And-Save 128 128 "$tauriDir\128x128.png"
    Resize-And-Save 256 256 "$tauriDir\128x128@2x.png"
    Resize-And-Save 512 512 "$tauriDir\icon.png"
    Resize-And-Save 30 30 "$tauriDir\Square30x30Logo.png"
    Resize-And-Save 44 44 "$tauriDir\Square44x44Logo.png"
    Resize-And-Save 71 71 "$tauriDir\Square71x71Logo.png"
    Resize-And-Save 89 89 "$tauriDir\Square89x89Logo.png"
    Resize-And-Save 107 107 "$tauriDir\Square107x107Logo.png"
    Resize-And-Save 142 142 "$tauriDir\Square142x142Logo.png"
    Resize-And-Save 150 150 "$tauriDir\Square150x150Logo.png"
    Resize-And-Save 284 284 "$tauriDir\Square284x284Logo.png"
    Resize-And-Save 310 310 "$tauriDir\Square310x310Logo.png"
    Resize-And-Save 50 50 "$tauriDir\StoreLogo.png"
}

# 2. Windows Package / MSIX Assets directories
$assetDirs = @(
    "C:\Dev\LinkProtection\Assets",
    "C:\Dev\LinkProtection\.winapp\candidate\Assets",
    "C:\Dev\LinkProtection\.winapp\debug\Assets"
)
foreach ($dir in $assetDirs) {
    Resize-And-Save 44 44 "$dir\AppList.png"
    Resize-And-Save 150 150 "$dir\MedTile.png"
    Resize-And-Save 50 50 "$dir\StoreLogo.png"
    Generate-Wide-Tile 310 150 120 "$dir\WideTile.png"
}

# 3. Extension icons
$extDir = "C:\Dev\LinkProtection\browser-extension\icons"
if (Test-Path $extDir) {
    Resize-And-Save 16 16 "$extDir\icon16.png"
    Resize-And-Save 32 32 "$extDir\icon32.png"
    Resize-And-Save 48 48 "$extDir\icon48.png"
    Resize-And-Save 128 128 "$extDir\icon128.png"
}

# 4. Generate Windows multi-resolution icon.ico (16, 24, 32, 48, 64 in DIB format, 256 in PNG)
function Build-Windows-Ico($sizes, $destIcoPath) {
    $imagesData = @()
    $entries = @()
    
    foreach ($sz in $sizes) {
        $bmp = New-Object System.Drawing.Bitmap($sz, $sz)
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
        $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $g.Clear([System.Drawing.Color]::Transparent)
        $g.DrawImage($img, 0, 0, $sz, $sz)
        $g.Dispose()

        if ($sz -eq 256) {
            # PNG encoded for 256x256
            $ms = New-Object System.IO.MemoryStream
            $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
            $rawBytes = $ms.ToArray()
            $ms.Dispose()
            $imagesData += ,$rawBytes
            
            $entry = [ordered]@{
                Width = 0 # 0 denotes 256
                Height = 0
                Colors = 0
                Reserved = 0
                Planes = 1
                Bpp = 32
                Size = $rawBytes.Length
            }
            $entries += $entry
        } else {
            # DIB encoded (BITMAPINFOHEADER + BGRA pixels + 1bpp AND mask) for standard Windows GDI compatibility
            $andStride = [Math]::Ceiling($sz / 32.0) * 4
            $andMaskSize = $andStride * $sz
            $xorSize = $sz * $sz * 4
            $headerSize = 40
            $totalDibSize = $headerSize + $xorSize + $andMaskSize

            $ms = New-Object System.IO.MemoryStream
            $bw = New-Object System.IO.BinaryWriter $ms

            # BITMAPINFOHEADER
            $bw.Write([uint32]40)              # biSize
            $bw.Write([int32]$sz)              # biWidth
            $bw.Write([int32]($sz * 2))        # biHeight (XOR + AND mask height)
            $bw.Write([uint16]1)               # biPlanes
            $bw.Write([uint16]32)              # biBitCount
            $bw.Write([uint32]0)               # biCompression (BI_RGB)
            $bw.Write([uint32]($xorSize + $andMaskSize)) # biSizeImage
            $bw.Write([int32]0)                # biXPelsPerMeter
            $bw.Write([int32]0)                # biYPelsPerMeter
            $bw.Write([uint32]0)               # biClrUsed
            $bw.Write([uint32]0)               # biClrImportant

            # Pixel data (bottom-up BGRA)
            for ($y = $sz - 1; $y -ge 0; $y--) {
                for ($x = 0; $x -lt $sz; $x++) {
                    $pixel = $bmp.GetPixel($x, $y)
                    $bw.Write([byte]$pixel.B)
                    $bw.Write([byte]$pixel.G)
                    $bw.Write([byte]$pixel.R)
                    $bw.Write([byte]$pixel.A)
                }
            }

            # AND mask (all zeros for 32bpp alpha icon)
            $andBytes = New-Object byte[] $andMaskSize
            $bw.Write($andBytes)

            $rawBytes = $ms.ToArray()
            $bw.Dispose()
            $ms.Dispose()

            $imagesData += ,$rawBytes

            $entry = [ordered]@{
                Width = $sz
                Height = $sz
                Colors = 0
                Reserved = 0
                Planes = 1
                Bpp = 32
                Size = $rawBytes.Length
            }
            $entries += $entry
        }

        $bmp.Dispose()
    }

    # Write ICO file
    $icoMs = New-Object System.IO.MemoryStream
    $icoBw = New-Object System.IO.BinaryWriter $icoMs

    # Header
    $icoBw.Write([uint16]0) # Reserved
    $icoBw.Write([uint16]1) # Type: 1 = ICO
    $icoBw.Write([uint16]$entries.Count)

    # Calculate offset of image data
    $headerSize = 6
    $entrySize = 16
    $currentOffset = $headerSize + ($entries.Count * $entrySize)

    for ($i = 0; $i -lt $entries.Count; $i++) {
        $e = $entries[$i]
        $icoBw.Write([byte]$e.Width)
        $icoBw.Write([byte]$e.Height)
        $icoBw.Write([byte]$e.Colors)
        $icoBw.Write([byte]$e.Reserved)
        $icoBw.Write([uint16]$e.Planes)
        $icoBw.Write([uint16]$e.Bpp)
        $icoBw.Write([uint32]$e.Size)
        $icoBw.Write([uint32]$currentOffset)
        $currentOffset += $e.Size
    }

    # Write image payloads
    for ($i = 0; $i -lt $imagesData.Count; $i++) {
        $icoBw.Write($imagesData[$i])
    }

    [System.IO.File]::WriteAllBytes($destIcoPath, $icoMs.ToArray())
    $icoBw.Dispose()
    $icoMs.Dispose()
    Write-Host "Generated multi-resolution ICO ($($sizes -join ', ')): $destIcoPath"
}

Build-Windows-Ico @(16, 24, 32, 48, 64, 256) "$tauriDir\icon.ico"

$img.Dispose()
Write-Host "All icons generated successfully!" -ForegroundColor Green
