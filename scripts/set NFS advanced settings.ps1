############################################################################
#written by Kevin Bickel
#Date: 22MAR16
############################################################################
#change these variables

foreach($esx in get-vmhost)
{
	get-advancedsetting -Entity $esx -Name NFS.MaxVolumes | set-advancedsetting -value "256" -confirm:$false
	get-advancedsetting -Entity $esx -Name NFS.HeartbeatMaxFailures | set-advancedsetting -value "10" -confirm:$false
	get-advancedsetting -Entity $esx -Name NFS.HeartbeatFrequency | set-advancedsetting -value "12" -confirm:$false
	get-advancedsetting -Entity $esx -Name NFS.HeartbeatTimeout | set-advancedsetting -value "5" -confirm:$false
	get-advancedsetting -Entity $esx -Name NFS.MaxQueueDepth | set-advancedsetting -value "128" -confirm:$false
	get-advancedsetting -Entity $esx -Name Net.TcpipHeapSize | set-advancedsetting -value "32" -confirm:$false
	get-advancedsetting -Entity $esx -Name Net.TcpipHeapMax | set-advancedsetting -value "1024" -confirm:$false
	get-advancedsetting -Entity $esx -Name Disk.QFullSampleSize | set-advancedsetting -value "32" -confirm:$false
	get-advancedsetting -Entity $esx -Name Disk.QFullThreshold | set-advancedsetting -value "8" -confirm:$false
	get-advancedsetting -Entity $esx -Name DataMover.HardwareAcceleratedInit | set-advancedsetting -value "1" -confirm:$false
    get-advancedsetting -Entity $esx -Name DataMover.HardwareAcceleratedMove | set-advancedsetting -value "1" -confirm:$false
    get-advancedsetting -Entity $esx -Name VMFS3.HardwareAcceleratedLocking | set-advancedsetting -value "1" -confirm:$false

}