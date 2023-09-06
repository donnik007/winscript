
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

#Reverse Stub Zone
A reverse DNS stub zone is a type of DNS zone that contains only resource records that identify the DNS servers for the reverse lookup zone. A reverse lookup zone is used to resolve IP addresses to host names. You can create a reverse DNS stub zone using the DNS server role in Windows Server1.

To create a reverse DNS stub zone, you need to follow these steps:

Open the DNS Management Console on your Windows Server and right-click on Reverse Lookup Zones and select New Zone.
Choose the Zone Type as Primary Zone or Secondary Zone, depending on whether you want to store the zone data in Active Directory or in a file.
Choose the Reverse Lookup Zone Name based on the network ID of the IP addresses you want to resolve. For example, if you want to create a reverse lookup zone for the network 10.1.2.0/24, you need to enter 2.1.10.in-addr.arpa as the zone name.
Choose the Zone File name or use the default name based on the zone name.
Specify the Master Servers that host the primary zone for the reverse lookup zone. You need to enter the IP addresses of the DNS servers that have authoritative information about the reverse lookup zone.
Finish the wizard and verify that the reverse DNS stub zone is created successfully.
You can also use PowerShell commands to create a reverse DNS stub zone. For example, to add a stub zone for the network 10.1.2.0/24 using the authoritative DNS server 172.23.90.124, you can run the following command:

Add-DnsServerStubZone -NetworkId 10.1.2.0/24 -MasterServers 172.23.90.124 -PassThru -ReplicationScope Forest

This command adds a stub zone for the network 2.1.10.in-addr.arpa, which is replicated to all DNS servers in the forest.

For more information and examples, you can refer to these articles:

Manage DNS zones using DNS server in Windows Server
Add-DnsServerStubZone (DnsServer) | Microsoft Learn
configure a subnetted reverse lookup zone - Windows Server
Configure DNS Reverse Lookup Zones and PTR Records (Step by Step Guide)
I hope this helps you with your task. If you have any other questions, feel free to ask me. 😊
