
# B2.M5 - DNS: Forward Stub Zones exist
if ($Aspect -eq "B2" -or $Aspect -eq "B2.M5" -or $Aspect -eq "B2M5" -or !$Aspect) {
    Initialize-Marking -Aspect "B2.M5" -Description "DNS: Forward Stub Zones exist"
    $B2M5 = Get-AspectResult -Ip 10.1.0.1 -Cmd 'Get-DnsServerZone | Where {$_.ZoneType -Eq ''Stub''}'
    Test-AspectResult -Aspect "B2.M5" -String $B2M5 -Expected "dk.skill39.wse; pl.skill39.wse"
    Start-Marking -Aspect "B2.M5"
}

# B2.M6 - DNS: Reverse Stub Zones exist
if ($Aspect -eq "B2" -or $Aspect -eq "B2.M6" -or $Aspect -eq "B2M6" -or !$Aspect) {
    Initialize-Marking -Aspect "B2.M6" -Description "DNS: Reverse Stub Zones exist"
    $B2M6 = Get-AspectResult -Ip 10.1.0.1 -Cmd 'Get-DnsServerZone | Where {$_.ZoneType -Eq ''Stub''}'
    Test-AspectResult -Aspect "B2.M6" -String $B2M6 -Expected "0.2.10.in-addr.arpa; 0.3.10.in-addr.arpa"
    Start-Marking -Aspect "B2.M6"
}
