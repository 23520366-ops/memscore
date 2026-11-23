param(
    [Parameter(Mandatory = $true)][string]$ExtractedDirectory,
    [string]$Iso = 'D:\MayAo\win11-tu-cai.iso',
    [string]$Oscdimg
)

$ErrorActionPreference = 'Stop'
$source = (Resolve-Path -LiteralPath $ExtractedDirectory).Path
$boot = Join-Path $source 'efi\microsoft\boot\efisys_noprompt.bin'
$wim = Join-Path $source 'sources\install.wim'
if (!(Test-Path -LiteralPath $wim -PathType Leaf)) { throw 'Missing sources\install.wim.' }
if (Test-Path -LiteralPath $Iso) { throw "Output file already exists: $Iso" }
if (!(Test-Path -LiteralPath $boot -PathType Leaf)) { throw 'Missing the unattended UEFI boot image.' }
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'autounattend.xml') -Destination $source

$partial = "$Iso.partial"
if (Test-Path -LiteralPath $partial) { throw "Partial output already exists: $partial" }
try {
    if ($Oscdimg) {
        & $Oscdimg '-m' '-o' '-u2' '-udfver102' '-pEF' "-b$boot" $source $partial
        if ($LASTEXITCODE -ne 0) { throw "Oscdimg failed with exit code $LASTEXITCODE." }
    } else {
        # UDF supports WIM files over 4 GiB. Stream the image in blocks.
        $fsi = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
        $fsi.FileSystemsToCreate = 4
        $fsi.UDFRevision = 0x102
        $fsi.FreeMediaBlocks = 4194304
        $fsi.VolumeName = 'WIN11_IE105'
        $bootStream = New-Object -ComObject ADODB.Stream
        $bootStream.Type = 1
        $bootStream.Open()
        $bootStream.LoadFromFile($boot)
        $options = New-Object -ComObject IMAPI2FS.BootOptions
        $options.AssignBootImage($bootStream)
        $options.PlatformId = 0xef
        $options.Emulation = 0
        $fsi.BootImageOptions = $options
        $bootStream.Close()
        $fsi.Root.AddTree($source, $false)
        $image = $fsi.CreateResultImage()

        Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

public static class MemScopeIsoWriter {
    public static void Write(string path, object image, long expectedBytes) {
        var source = (IStream)image;
        var buffer = new byte[1024 * 1024];
        IntPtr count = Marshal.AllocCoTaskMem(sizeof(int));
        try {
            using (var dest = new FileStream(path, FileMode.CreateNew, FileAccess.Write)) {
                while (dest.Position < expectedBytes) {
                    int size = (int)Math.Min(buffer.Length, expectedBytes - dest.Position);
                    source.Read(buffer, size, count);
                    int read = Marshal.ReadInt32(count);
                    if (read <= 0) throw new EndOfStreamException();
                    dest.Write(buffer, 0, read);
                }
            }
        } finally {
            Marshal.FreeCoTaskMem(count);
        }
    }
}
'@
        [MemScopeIsoWriter]::Write($partial, $image.ImageStream, [long]$image.TotalBlocks * $image.BlockSize)
    }
    Move-Item -LiteralPath $partial -Destination $Iso
    Get-Item -LiteralPath $Iso | Select-Object FullName, Length
} finally {
    if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial }
}
