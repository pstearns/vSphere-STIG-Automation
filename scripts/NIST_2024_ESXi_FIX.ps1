foreach($vmhost in get-vmhost)
{
    $esxcli = Get-EsxCli -v2 -vmhost $vmhost
    $arguments = $esxcli.system.tls.server.set.CreateArgs()
    $arguments.profile = "NIST_2024"
    $esxcli.system.tls.server.set.invoke($arguments)
}
