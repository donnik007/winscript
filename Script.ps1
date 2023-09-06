Param (
    [string]$Aspect
)

Function Get-AspectResult {
    Param (
        [string]$Ip,
        [string]$JumpIp,
        [string]$Cmd,
        [string]$User="Administrator",
        [string]$JumpUser="Administrator",
        [string]$SshKey="C:\Marking\moduleb",
        [switch]$Red=$False,
        [switch]$Local=$False
    )
    Write-Host "Running command: $Cmd"
    if ($Local) {
        $output = try { Invoke-Expression $Cmd } catch { Write-Host "Command: $Cmd threw an error" }
    } elseif ($JumpIp) {
        $output = ssh -o ProxyCommand="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i $SshKey -W %h:%p $JumpUser@$JumpIp" -i $SshKey $User@$Ip "try { $Cmd } catch { Write-Host 'Command: "$Cmd" threw an error' }"
    } else {
        $output = ssh -o "StrictHostKeyChecking=no" -i $SshKey $User@$Ip "try { $Cmd } catch { Write-Host 'Command: "$Cmd" threw an error' }"
    }

    if ($output -like "Command: *") {
        Write-Host $output | Out-String
        return 1
    } 
    return $output | Out-String
}

Function Test-AspectResult {
    Param (
        [string]$Aspect,
        [string]$String,
        [string]$Expected,
        [switch]$Manual=$False
    )
    if ($String -eq 1 -or $String -Like " 1") {
        Write-Host "Testing aspect $Aspect failed" -ForegroundColor Red
    } else {
        if ($Manual) {
            Write-Host "!!! MANUAL TESTING !!!"
        }

        Write-Host "Expected output: $Expected" -ForegroundColor Red
        
        if (!($Manual)) {
            Write-Host "Actual output:"
            Write-Host $String
        }
    }

}

Function Initialize-Marking {
    Param (
        [string]$Aspect,
        [string]$Description
    )
    Clear-Host
    Write-Host "----------------------------------------------------------"
    Write-Host
    Write-Host "Testing aspect $Aspect"
    Write-Host "$Description"
}

Function Start-Marking {
    Param (
        [string]$Aspect
    )

    Write-Host "Please mark now aspect " -NoNewline
    Write-Host "$Aspect" -ForegroundColor Red
    $confirmation = Read-Host "Move to the next aspect? [y/n]"
    while($confirmation -ne "y")
    {
        if ($confirmation -eq 'n') { exit }
        $confirmation = Read-Host "Move to the next aspect? [y/n]"
    }
}

# B1.M1 - Firewall: DK-FW external IP is reachable
if ($Aspect -eq "B1" -or $Aspect -eq "B1.M1" -or $Aspect -eq "B1M1" -or !$Aspect) {
    Initialize-Marking -Aspect "B1.M1" -Description "Firewall: DK-FW external IP is reachable"
    $B1M1 = Get-AspectResult -Ip 10.1.0.254 -Cmd "(Test-NetConnection 198.51.100.31).PingSucceeded"
    Test-AspectResult -Aspect "B1.M1" -String $B1M1 -Expected "TRUE"
    Start-Marking -Aspect "B1.M1"
}

# B1.M2 - RAS: PL-FW internal IP is reachable
if ($Aspect -eq "B1" -or $Aspect -eq "B1.M2" -or $Aspect -eq "B1M2" -or !$Aspect) {
    Initialize-Marking -Aspect "B1.M2" -Description "RAS: PL-FW internal IP is reachable"
    $B1M2 = Get-AspectResult -Ip 10.1.0.254 -Cmd "(Test-NetConnection 10.2.0.254).PingSucceeded"
    Test-AspectResult -Aspect "B1.M2" -String $B1M2 -Expected "TRUE"
    Start-Marking -Aspect "B1.M2"
}

# B1.M3 - RAS: DK-DC internal IP is reachable
if ($Aspect -eq "B1" -or $Aspect -eq "B1.M3" -or $Aspect -eq "B1M3" -or !$Aspect) {
    Initialize-Marking -Aspect "B1.M3" -Description "RAS: DK-DC internal IP is reachable"
    $B1M3 = Get-AspectResult -Ip 10.1.0.254 -Cmd "(Test-NetConnection 10.3.0.1).PingSucceeded"
    Test-AspectResult -Aspect "B1.M3" -String $B1M3 -Expected "TRUE"
    Start-Marking -Aspect "B1.M3"
}

# B1.M4 - RAS: S2S interfaces are persistent
if ($Aspect -eq "B1" -or $Aspect -eq "B1.M4" -or $Aspect -eq "B1M4" -or !$Aspect) {
    Initialize-Marking -Aspect "B1.M4" -Description "RAS: S2S interfaces are persistent"
    $B1M4 = Get-AspectResult -Ip 10.1.0.254 -Cmd "Get-VpnS2SInterface | Select Name, Destination, Persistent"
    Test-AspectResult -Aspect "B1.M4" -String $B1M4 -Expected "Interface is persistent"
    Start-Marking -Aspect "B1.M4"
}

# B2.M1 - ADDS: skill39.wse forest root
if ($Aspect -eq "B2" -or $Aspect -eq "B2.M1" -or $Aspect -eq "B2M1" -or !$Aspect) {
    Initialize-Marking -Aspect "B2.M1" -Description "ADDS: skill39.wse forest root"
    $B2M1 = Get-AspectResult -Ip 10.1.0.1 -Cmd "Get-ADForest | Select RootDomain, SchemaMaster"
    Test-AspectResult -Aspect "B2.M1" -String $B2M1 -Expected "Rootdomain skill39.wse, SchemaMaster CLOUD-DC"
    Start-Marking -Aspect "B2.M1"
}

# B2.M2 - DNS: A records exist
if ($Aspect -eq "B2" -or $Aspect -eq "B2.M2" -or $Aspect -eq "B2M2" -or !$Aspect) {
    Initialize-Marking -Aspect "B2.M2" -Description "DNS: A records exist"
    $B2M2 = Get-AspectResult -Ip 10.1.0.1 -Cmd "Get-DnsServerResourceRecord -ZoneName skill39.wse -RRType A"
    Test-AspectResult -Aspect "B2.M2" -String $B2M2 -Expected "cloud-dc > .1, cloud-fw > .254, cloud-rootca > .5"
    Start-Marking -Aspect "B2.M2"
}

# B2.M3 - DNS: PTR records exist
if ($Aspect -eq "B2" -or $Aspect -eq "B2.M3" -or $Aspect -eq "B2M3" -or !$Aspect) {
    Initialize-Marking -Aspect "B2.M3" -Description "DNS: PTR records exist"
    $B2M3 = Get-AspectResult -Ip 10.1.0.1 -Cmd "Get-DnsServerResourceRecord -ZoneName 0.1.10.in-addr.arpa -RRType PTR | Format-Table -AutoSize"
    Test-AspectResult -Aspect "B2.M3" -String $B2M3 -Expected "1 > cloud-dc, 254 > cloud-fw, 5 > cloud-rootca"
    Start-Marking -Aspect "B2.M3"
}

# B2.M4 - DNS: CNAME records exist
if ($Aspect -eq "B2" -or $Aspect -eq "B2.M4" -or $Aspect -eq "B2M4" -or !$Aspect) {
    Initialize-Marking -Aspect "B2.M4" -Description "DNS: CNAME records exist"
    $B2M4 = Get-AspectResult -Ip 10.1.0.1 -Cmd "Get-DnsServerResourceRecord -ZoneName skill39.wse -RRType CNAME | Format-Table -AutoSize"
    Test-AspectResult -Aspect "B2.M4" -String $B2M4 -Expected "cacerts > cloud-dc, crl > cloud-dc"
    Start-Marking -Aspect "B2.M4"
}

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

# B2.M7 - ADCS: Root CA CDP location
if ($Aspect -eq "B2" -or $Aspect -eq "B2.M7" -or $Aspect -eq "B2M7" -or !$Aspect) {
    Initialize-Marking -Aspect "B2.M7" -Description "ADCS: Root CA CDP location"
    $B2M7 = Get-AspectResult -Ip 10.1.0.1 -Cmd 'Invoke-WebRequest -Uri http://crl.skill39.wse/Skill39-CA.crl -OutFile Skill39-CA.crl | certutil Skill39-CA.crl | Select-String CN, ThisUpdate, CRL'
    Test-AspectResult -Aspect "B2.M7" -String $B2M7 -Expected "Output exists with CRL information"
    Start-Marking -Aspect "B2.M7"
}

# B2.M8 - ADCS: Root CA AIA location
if ($Aspect -eq "B2" -or $Aspect -eq "B2.M8" -or $Aspect -eq "B2M8" -or !$Aspect) {
    Initialize-Marking -Aspect "B2.M8" -Description "ADCS: Root CA AIA location"
    $B2M8 = Get-AspectResult -Ip 10.1.0.1 -Cmd 'Invoke-WebRequest -Uri http://cacerts.skill39.wse/Skill39-CA.crt -OutFile Skill39-CA.crt | certutil Skill39-CA.crt | Select-String CA'
    Test-AspectResult -Aspect "B2.M8" -String $B2M8 -Expected "Output exists with CA information"
    Start-Marking -Aspect "B2.M8"
}

# B2.M9 - ADCS: Root CA Common Name
if ($Aspect -eq "B2" -or $Aspect -eq "B2.M9" -or $Aspect -eq "B2M9" -or !$Aspect) {
    Initialize-Marking -Aspect "B2.M9" -Description "ADCS: Root CA Common Name"
    $B2M9 = Get-AspectResult -Ip 10.1.0.1 -Cmd 'Invoke-WebRequest -Uri http://cacerts.skill39.wse/Skill39-CA.crt -OutFile Skill39-CA.crt | certutil Skill39-CA.crt | Select-String CN'
    Test-AspectResult -Aspect "B2.M9" -String $B2M9 -Expected "CN=Skill39-CA"
    Start-Marking -Aspect "B2.M9"
}

# B2.M10 - Automation: Script is running every 2 minutes
if ($Aspect -eq "B2" -or $Aspect -eq "B2.M10" -or $Aspect -eq "B2M10" -or !$Aspect) {
    Initialize-Marking -Aspect "B2.M10" -Description "Automation: Script is running every 2 minutes"
    Test-AspectResult -Manual $True -Aspect "B2.M10" -Expected "CSV file is updated/crated to defined location every 2 minutes"
    Start-Marking -Aspect "B2.M10"
}

# B2.M11 - Automation: Script generates CSV file of users in Skill39 Enterprise who haven't logged in
if ($Aspect -eq "B2" -or $Aspect -eq "B2.M11" -or $Aspect -eq "B2M11" -or !$Aspect) {
    Initialize-Marking -Aspect "B2.M11" -Description "Automation: Script generates CSV file of users in Skill39 Enterprise who haven't logged in"
    Test-AspectResult -Manual $True -Aspect "B2.M11" -Expected "`n 0 - There is no CSV file or CSV file is empty `n 1 - CSV file includes list of users who haven't logged in for atleast one domain `n 2 - CSV file includes list of users who haven't logged in for root and child domains `n 3 - Script runs without errors and has extra feature added, e.g. comments, etc"
    Start-Marking -Aspect "B2.M11"
}

# B3.M1 - ADCS: Machine network interface is disabled
if ($Aspect -eq "B3" -or $Aspect -eq "B3.M1" -or $Aspect -eq "B3M1" -or !$Aspect) {
    Initialize-Marking -Aspect "B3.M1" -Description "ADCS: Machine network interface is disabled"
    Test-AspectResult -Aspect "B3.M1" -Expected "CLOUD-ROOTCA VM network adapter is disabled" -Manual $True
    Start-Marking -Aspect "B3.M1"
}

# B4.M1 - Firewall: CLOUD-FW external IP is reachable
if ($Aspect -eq "B4" -or $Aspect -eq "B4.M1" -or $Aspect -eq "B4M1" -or !$Aspect) {
    Initialize-Marking -Aspect "B4.M1" -Description "Firewall: CLOUD-FW external IP is reachable"
    $B4M1 = Get-AspectResult -Ip 10.2.0.254 -Cmd '(Test-NetConnection 198.51.100.11).PingSucceeded'
    Test-AspectResult -Aspect "B4.M1" -String $B4M1 -Expected "TRUE"
    Start-Marking -Aspect "B4.M1"
}

# B4.M2 - RAS: DK-DC internal IP is reachable
if ($Aspect -eq "B4" -or $Aspect -eq "B4.M2" -or $Aspect -eq "B4M2" -or !$Aspect) {
    Initialize-Marking -Aspect "B4.M2" -Description "RAS: DK-DC internal IP is reachable"
    $B4M2 = Get-AspectResult -Ip 10.2.0.254 -Cmd '(Test-NetConnection 10.3.0.1).PingSucceeded'
    Test-AspectResult -Aspect "B4.M2" -String $B4M2 -Expected "TRUE"
    Start-Marking -Aspect "B4.M2"
}

# B5.M1 - ADDS: pl.skill39.wse child domain
if ($Aspect -eq "B5" -or $Aspect -eq "B5.M1" -or $Aspect -eq "B5M1" -or !$Aspect) {
    Initialize-Marking -Aspect "B5.M1" -Description "ADDS: pl.skill39.wse child domain"
    $B5M1 = Get-AspectResult -Ip 10.2.0.1 -Cmd 'Get-ADDomain | Select ParentDomain, DistinguishedName'
    Test-AspectResult -Aspect "B5.M1" -String $B5M1 -Expected "DC=pl,DC=skill39,DC=wse"
    Start-Marking -Aspect "B5.M1"
}

# B5.M2 - GPO: ADMX template files added
if ($Aspect -eq "B5" -or $Aspect -eq "B5.M2" -or $Aspect -eq "B5M2" -or !$Aspect) {
    Initialize-Marking -Aspect "B5.M2" -Description "GPO: ADMX template files added"
    $B5M2 = Get-AspectResult -Ip 10.2.0.1 -Cmd 'Test-Path C:\Windows\SYSVOL\domain\Policies\PolicyDefinitions\Windows.admx'
    Test-AspectResult -Aspect "B5.M2" -String $B5M2 -Expected "TRUE"
    Start-Marking -Aspect "B5.M2" 
}

# B5.M3 - GPO: PowerShell remoting to DK-CLIENT works
if ($Aspect -eq "B5" -or $Aspect -eq "B5.M3" -or $Aspect -eq "B5M3" -or !$Aspect) {
    Initialize-Marking -Aspect "B5.M3" -Description "GPO: PowerShell remoting to DK-CLIENT works"
    $B8M9 = Get-AspectResult -Ip 10.3.0.1 -Cmd 'Test-WSMan -ComputerName DK-CLIENT'
    Test-AspectResult -Aspect "B5.M3" -String $B8M9 -Expected "Output with WinRM protocol information"
    Start-Marking -Aspect "B5.M3"
}

# B5.M4 - 

# B5.J1 - ADDS: Imported users from the excel file with correct parameters
if ($Aspect -eq "B5" -or $Aspect -eq "B5.J1" -or $Aspect -eq "B5J1" -or !$Aspect) {
    Initialize-Marking -Aspect "B5.J1" -Description "ADDS: Imported users from the excel file with correct parameters"
    Test-AspectResult -Aspect "B5.J1" -Manual $True -Expected "`n 0 - Users are not imported `n 1 - Users have been imported `n 2 - Users have been imported with correct parameters `n 3 - Users and groups have structured in AD logically under separate OUs `n"
    Start-Marking -Aspect "B5.J1"
}

# B6.M1 - Storage: Disk is mounted to C:\Files
if ($Aspect -eq "B6" -or $Aspect -eq "B6.M1" -or $Aspect -eq "B6M1" -or !$Aspect) {
    Initialize-Marking -Aspect "B6.M1" -Description "Storage: Disk is mounted to C:\Files"
    $B6M1 = Get-AspectResult -Ip 10.2.0.20 -Cmd '(Get-WmiObject Win32_Volume).Name | Select-String Files'
    Test-AspectResult -Aspect "B6.M1" -String $B6M1 -Expected "C:\Files\"
    Start-Marking -Aspect "B6.M1"
}

# B6.M2 - File: DFS Namespace root "dfs" exist
if ($Aspect -eq "B6" -or $Aspect -eq "B6.M2" -or $Aspect -eq "B6M3" -or !$Aspect) {
    Initialize-Marking -Aspect "B6.M2" -Description 'File: DFS Namespace root "dfs" exist'
    $B6M2 = Get-AspectResult -Ip 10.2.0.1 -Cmd '(Get-DfsnRoot).Path'
    Test-AspectResult -Aspect "B6.M2" -String $B6M2 -Expected '\\pl.skill39.wse\dfs'
    Start-Marking -Aspect "B6.M2"
}

# B6.M3 - File: DFS Namespace has department shares folders
if ($Aspect -eq "B6" -or $Aspect -eq "B6.M3" -or $Aspect -eq "B6M4" -or !$Aspect) {
    Initialize-Marking -Aspect "B6.M3" -Description 'File: DFS Namespace has department shares folders'
    $B6M3 = Get-AspectResult -Ip 10.2.0.1 -Cmd 'Get-DfsnFolder -Path ''\\pl.skill39.wse\dfs\*'''
    Test-AspectResult -Aspect "B6.M3" -String $B6M3 -Expected "`n \\pl.skill39.wse\dfs\Experts `n \\pl.skill39.wse\dfs\Competitors `n \\pl.skill39.wse\dfs\Managers `n"
    Start-Marking -Aspect "B6.M3"
}

# B6.M4 - File: DFS Replication is configured between PL-SRV and PL-DC
if ($Aspect -eq "B6" -or $Aspect -eq "B6.M4" -or $Aspect -eq "B6M5" -or !$Aspect) {
    Initialize-Marking -Aspect "B6.M4" -Description 'File: DFS Replication is configured between PL-SRV and PL-DC'
    $B6M4 = Get-AspectResult -Ip 10.2.0.1 -Cmd 'Get-DfsrConnection | Select GroupName, SourceComputerName, DestinationComputerName'
    Test-AspectResult -Aspect "B6.M4" -String $B6M4 -Expected "There is 6 DFS connections, two for each share"
    Start-Marking -Aspect "B6.M4"
}

# B6.M5 - File: DFS share local paths are correct
if ($Aspect -eq "B6" -or $Aspect -eq "B6.M5" -or $Aspect -eq "B6M6" -or !$Aspect) {
    Initialize-Marking -Aspect "B6.M5" -Description "File: DFS share local paths are correct"
    $B6M5 = Get-AspectResult -Ip 10.2.0.1 -Cmd 'Get-DfsnFolderTarget ''\\pl.skill39.wse\dfs\Experts'''
    Test-AspectResult -Aspect "B6.M5" -String $B6M5 -Expected "`n TargetPath: `n \\pl-srv.pl.skill39.wse\Experts `n \\pl-dc.pl.skill39.wse\Experts `n"
    Start-Marking -Aspect "B6.M5"
}

# B6.M6 - DHCP: Configured according to PL infrastructure
if ($Aspect -eq "B6" -or $Aspect -eq "B6.M6" -or $Aspect -eq "B6M7" -or !$Aspect) {
    Initialize-Marking -Aspect "B6.M6" -Description "DHCP: Configured according to PL infrastructure"
    $B6M6 = Get-AspectResult -Ip 10.2.0.20 -Cmd 'Get-DhcpServerv4OptionValue -ScopeId ''10.2.0.0'' | Select OptionId, Name, Value'
    Test-AspectResult -Aspect "B6.M6" -String $B6M6 -Expected "`n Router - 10.2.0.254 `n DNS Domain Name - pl.skill39.wse `n DNS Servers - 10.2.0.1 `n"
    Start-Marking -Aspect "B6.M6"
}

# B6.M7 - DHCP: Pool range 10.2.0.100-10.2.0.150
if ($Aspect -eq "B6" -or $Aspect -eq "B6.M7" -or $Aspect -eq "B6M8" -or !$Aspect) {
    Initialize-Marking -Aspect "B6.M7" -Description "DHCP: Pool range 10.2.0.100-10.2.0.150"
    $B6M7 = Get-AspectResult -Ip 10.2.0.20 -Cmd 'Get-DhcpServerv4Scope | Select StartRange, EndRange'
    Test-AspectResult -Aspect "B6.M7" -String $B6M7 -Expected "Start - 10.2.0.100; End - 10.2.0.150"
    Start-Marking -Aspect "B6.M7"
}

# B7.M1 - Web: User can access http://web.dk.skill39.wse
if ($Aspect -eq "B7" -or $Aspect -eq "B7.M1" -or $Aspect -eq "B7M1" -or !$Aspect) {
    Initialize-Marking -Aspect "B7.M1" -Description "Web: User can access http://web.dk.skill39.wse"
    Test-AspectResult -Manual $True -Aspect "B7.M1" -Expected "PL-CLIENT: Try to log-in with user account into web portal at http://web.dk.skill39.wse"
    Start-Marking -Aspect "B7.M1"
}

# B7.M2 - Web: User can access http://web.dk.skill39.wse
if ($Aspect -eq "B7" -or $Aspect -eq "B7.M2" -or $Aspect -eq "B7M2" -or !$Aspect) {
    Initialize-Marking -Aspect "B7.M2" -Description "Web: User can access https://web.dk.skill39.wse"
    Test-AspectResult -Manual $True -Aspect "B7.M2" -Expected "PL-CLIENT: Try to log-in with user account into web portal at https://web.dk.skill39.wse"
    Start-Marking -Aspect "B7.M2"
}

# B7.M3 - File: User is unable to access other department shares
if ($Aspect -eq "B7" -or $Aspect -eq "B7.M3" -or $Aspect -eq "B7M3" -or !$Aspect) {
    Initialize-Marking -Aspect "B7.M3" -Description "File: User is unable to access other department shares"
    Test-AspectResult -Manual $True -Aspect "B7.M3" -Expected "PL-CLIENT: Competitor role account is unable to access \\pl.skill39.wse\dfs\Experts"
    Start-Marking -Aspect "B7.M3"
}

# B7.M4 - GPO: Network Drive is mapped respectively to the user department
if ($Aspect -eq "B7" -or $Aspect -eq "B7.M4" -or $Aspect -eq "B7M4" -or !$Aspect) {
    Initialize-Marking -Aspect "B7.M4" -Description "GPO: Network Drive is mapped respectively to the user department"
    Test-AspectResult -Manual $True -Aspect "B7.M4" -Expected 'PL-CLIENT: Competitor role has competitor share mapped under G: drive. Get-PSDrive | Where { $_.Name -Eq ''G''}'
    Start-Marking -Aspect "B7.M4"
}

# B7.M5 - GPO: First Sign-In Animation is disabled
if ($Aspect -eq "B7" -or $Aspect -eq "B7.M5" -or $Aspect -eq "B7M5" -or !$Aspect) {
    Initialize-Marking -Aspect "B7.M5" -Description "GPO: First Sign-In Animation is disabled"
    $B7M5 = Get-AspectResult -User "pl\administrator" -Ip "PL-CLIENT.PL.SKILL39.WSE" -Cmd '(Get-ItemProperty ''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'').EnableFirstLogonAnimation'
    Test-AspectResult -Aspect "B7.M5" -String $B7M5 -Expected "0"
    Start-Marking -Aspect "B7.M5"
}

# B7.M6 - GPO: Telemetery level is set to Enhanced
if ($Aspect -eq "B7" -or $Aspect -eq "B7.M6" -or $Aspect -eq "B7M6" -or !$Aspect) {
    Initialize-Marking -Aspect "B7.M6" -Description "GPO: Telemetery level is set to Enhanced"
    $B7M6 = Get-AspectResult -User "pl\administrator" -Ip "PL-CLIENT.PL.SKILL39.WSE" -Cmd '(Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection").AllowTelemetry'
    Test-AspectResult -Aspect "B7.M6" -String $B7M6 -Expected "2"
    Start-Marking -Aspect "B7.M6"
}

# B7.M7 - GPO: Most used is hidden from Start Menu
if ($Aspect -eq "B7" -or $Aspect -eq "B7.M7" -or $Aspect -eq "B7M7" -or !$Aspect) {
    Initialize-Marking -Aspect "B7.M7" -Description "GPO: Most used is hidden from Start Menu"
    Test-AspectResult -Manual $True -Aspect "B7.M7" -Expected "PL-CLIENT: Start Menu settings have Most used list disabled"
    Start-Marking -Aspect "B7.M7"
}

# B7.M8 - GPO: Edge homepage and start-up page is web.dk.skill39.wse
if ($Aspect -eq "B7" -or $Aspect -eq "B7.M8" -or $Aspect -eq "B7M8" -or !$Aspect) {
    Initialize-Marking -Aspect "B7.M8" -Description "GPO: Edge homepage and start-up page is web.dk.skill39.wse"
    Test-AspectResult -Manual $True -Aspect "B7.M8" -Expected "PL-CLIENT: Edge opens web.dk.skill39.wse"
    Start-Marking -Aspect "B7.M8"
}

# B7.M9 - GPO: dk-client.dk.skill39.wse is reachable
if ($Aspect -eq "B7" -or $Aspect -eq "B7.M9" -or $Aspect -eq "B7M9" -or !$Aspect) {
    Initialize-Marking -Aspect "B7.M9" -Description "GPO: dk-client.dk.skill39.wse is reachable"
    $B7M9 = Get-AspectResult -User "pl\administrator" -Ip "PL-CLIENT.PL.SKILL39.WSE" -Cmd '$ProgressPreference = ''SilentlyContinue''; (Test-NetConnection dk-client.dk.skill39.wse).PingSucceeded'
    Test-AspectResult -Aspect "B7.M9" -String $B7M9 -Expected "TRUE"
    Start-Marking -Aspect "B7.M9"
}

# B7.M10 - RDS: Wordpad is accessible for PL Competitors
if ($Aspect -eq "B7" -or $Aspect -eq "B7.M10" -or $Aspect -eq "B7M10" -or !$Aspect) {
    Initialize-Marking -Aspect "B7.M10" -Description "RDS: Wordpad is accessible for PL Competitors"
    Test-AspectResult -Manual $True -Aspect "B7.M10" -Expected "`n Access https://rds.dk.skill39.wse/RDWeb `n Log-in with Competitor role account and try to open Wordpad `n Notepad is not avalable in RDWeb `n"
    Start-Marking -Aspect "B7.M10"
}

# B8.M1 - ADDS: dk.skill39.wse child domain
if ($Aspect -eq "B8" -or $Aspect -eq "B8.M1" -or $Aspect -eq "B8M1" -or !$Aspect) {
    Initialize-Marking -Aspect "B8.M1" -Description "ADDS: dk.skill39.wse child domain"
    $B8M1 = Get-AspectResult -Ip 10.3.0.1 -Cmd 'Get-ADDomain | Select ParentDomain, DistinguishedName'
    Test-AspectResult -Aspect "B8.M1" -String $B8M1 -Expected "DC=dk,DC=skill39,DC=wse"
    Start-Marking -Aspect "B8.M1"
}

# B8.M2 - ADCS: DK SubCA certificate has correct parameters
if ($Aspect -eq "B8" -or $Aspect -eq "B8.M2" -or $Aspect -eq "B8M2" -or !$Aspect) {
    Initialize-Marking -Aspect "B8.M2" -Description "ADCS: DK SubCA certificate has correct parameters"
    $B8M2 = Get-AspectResult -Ip 10.3.0.1 -Cmd 'certutil -ping DK-DC.dk.skill39.wse\Skill39-DK-CA; (Get-CACrlDistributionPoint | Where AddtoCertificateCdp).Uri; (Get-CAAuthorityInformationAccess).Uri'
    Test-AspectResult -Aspect "B8.M2" -String $B8M2 -Expected "`n Interface is alive `n CRL and AIA paths are correct (4 in total)"
    Start-Marking -Aspect "B8.M2"
}

# B8.M3 - ADCS: CRL validity period is correct
if ($Aspect -eq "B8" -or $Aspect -eq "B8.M3" -or $Aspect -eq "B8M3" -or !$Aspect) {
    Initialize-Marking -Aspect "B8.M3" -Description "ADCS: CRL validity period is correct"
    $B8M3 = Get-AspectResult -Ip 10.3.0.1 -Cmd 'certutil -getreg ca\val*'
    Test-AspectResult -Aspect "B8.M3" -String $B8M3 -Expected "`n ValidityPeriod - Years `n PeriodUnits - 5 `n"
    Start-Marking -Aspect "B8.M3"
}

# B8.M4 - File: SMB witness share exist
if ($Aspect -eq "B8" -or $Aspect -eq "B8.M4" -or $Aspect -eq "B8M4" -or !$Aspect) {
    Initialize-Marking -Aspect "B8.M4" -Description "File: SMB witness share exist"
    $B8M4 = Get-AspectResult -Ip 10.3.0.1 -Cmd 'Get-SmbShare | Where { $_.Name -eq ''witness'' }'
    Test-AspectResult -Aspect "B8.M4" -String $B8M4 -Expected "witness share exist"
    Start-Marking -Aspect "B8.M4"
}

# B8.M5 - RDS: Web page is accessible at https://rds.dk.skill39.wse
if ($Aspect -eq "B8" -or $Aspect -eq "B8.M5" -or $Aspect -eq "B8M5" -or !$Aspect) {
    Initialize-Marking -Aspect "B8.M5" -Description "RDS: Web page is accessible at https://rds.dk.skill39.wse"
    $B8M5 = Get-AspectResult -Ip 10.3.0.1 -Cmd '(Invoke-WebRequest -Uri https://rds.dk.skill39.wse/RDWeb).Content.Split([Environment]::NewLine) | Select-String ''WorkSpaceID'''
    Test-AspectResult -Aspect "B8.M5" -String $B8M5 -Expected "HTML output with WorkSpaceID"
    Start-Marking -Aspect "B8.M5"
}

# B8.M6 - RDS: Web page certificate is issued by DK-Server template
if ($Aspect -eq "B8" -or $Aspect -eq "B8.M6" -or $Aspect -eq "B8M6" -or !$Aspect) {
    Initialize-Marking -Aspect "B8.M6" -Description "RDS: Web page certificate is issued by DK-Server template"
    $B8M6 = Get-AspectResult -Ip 10.3.0.1 -Cmd 'Import-Module WebAdministration; $thumbprint = (Get-ChildItem IIS:SSLBindings | Where { $_.Port -Like 443 }).Thumbprint; $cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where { $_.Thumbprint -eq $thumbprint }; ($cert.Extensions | Where { $_.Oid.FriendlyName -eq ''Certificate Template Information'' }).Format(0)'
    Test-AspectResult -Aspect "B8.M6" -String $B8M6 -Expected "Template=DK-Server"
    Start-Marking -Aspect "B8.M6"
}

# B8.M7 - RDS: All terminal services are signed by Skill39-DK-CA - Executing through ssh may fail, even though it is working as expected
if ($Aspect -eq "B8" -or $Aspect -eq "B8.M7" -or $Aspect -eq "B8M7" -or !$Aspect) {
    Initialize-Marking -Aspect "B8.M7" -Description "RDS: All terminal services are signed by Skill39-DK-CA"
    $B8M7 = Get-AspectResult -Ip 10.3.0.1 -Cmd 'Get-RDCertificate | Select Role, Subject, IssuedBy'
    Test-AspectResult -Aspect "B8.M7" -String $B8M7 -Expected "RDRedictor, RDPublishing, RDWebAccess issued by Skill39-DK-CA"
    Start-Marking -Aspect "B8.M7"
}

# B8.M8 - RDS: Notepad and Wordpad has been published - Executing through ssh may fail, even though it is working as expected.
if ($Aspect -eq "B8" -or $Aspect -eq "B8.M8" -or $Aspect -eq "B8M8" -or !$Aspect) {
    Initialize-Marking -Aspect "B8.M8" -Description "RDS: Notepad and Wordpad has been published"
    $B8M8 = Get-AspectResult -Ip 10.3.0.1 -Cmd 'Get-RDRemoteApp'
    Test-AspectResult -Aspect "B8.M8" -String $B8M8 -Expected "WordPad and Notepad are published"
    Start-Marking -Aspect "B8.M8"
}

# B8.M9 - GPO: PowerShell remoting to DK-CLIENT works
if ($Aspect -eq "B8" -or $Aspect -eq "B8.M9" -or $Aspect -eq "B8M9" -or !$Aspect) {
    Initialize-Marking -Aspect "B8.M9" -Description "GPO: PowerShell remoting to DK-CLIENT works"
    $B8M9 = Get-AspectResult -Ip 10.3.0.1 -Cmd 'Test-WSMan -ComputerName DK-CLIENT'
    Test-AspectResult -Aspect "B8.M9" -String $B8M9 -Expected "Output with WinRM protocol information"
    Start-Marking -Aspect "B8.M9"
}

# B8.M10 - DHCP: Configured according to DK infrastructure
if ($Aspect -eq "B8" -or $Aspect -eq "B8.M10" -or $Aspect -eq "B8M10" -or !$Aspect) {
    Initialize-Marking -Aspect "B8.M10" -Description "DHCP: Configured according to PL infrastructure"
    $B8M10 = Get-AspectResult -Ip 10.3.0.1 -Cmd 'Get-DhcpServerv4OptionValue -ScopeId ''10.3.0.0'' | Select OptionId, Name, Value'
    Test-AspectResult -Aspect "B8.M10" -String $B8M10 -Expected "`n Router - 10.3.0.254 `n DNS Domain Name - pl.skill39.wse `n DNS Servers - 10.3.0.1 `n"
    Start-Marking -Aspect "B8.M10"
}

# B8.M11 - DHCP: Pool range 10.3.0.100-10.3.0.150
if ($Aspect -eq "B8" -or $Aspect -eq "B8.M11" -or $Aspect -eq "B8M11" -or !$Aspect) {
    Initialize-Marking -Aspect "B8.M11" -Description "DHCP: Pool range 10.3.0.100-10.3.0.150"
    $B8M11 = Get-AspectResult -Ip 10.3.0.1 -Cmd 'Get-DhcpServerv4Scope | Select StartRange, EndRange'
    Test-AspectResult -Aspect "B8.M11" -String $B8M11 -Expected "Start - 10.3.0.100; End - 10.3.0.150"
    Start-Marking -Aspect "B8.M11"
}


# B8.J1 - ADDS: Imported users from the excel file with correct parameters
if ($Aspect -eq "B8" -or $Aspect -eq "B8.J1" -or $Aspect -eq "B8J1" -or !$Aspect) {
    Initialize-Marking -Aspect "B8.J1" -Description "ADDS: Imported users from the excel file with correct parameters"
    Test-AspectResult -Aspect "B8.J1" -Manual $True -Expected "`n 0 - Users are not imported `n 1 - Users have been imported `n 2 - Users have been imported with correct parameters `n 3 - Users and groups have structured in AD logically under separate OUs `n"
    Start-Marking -Aspect "B8.J1"
}

# B9.M1 - Storage: Disk is mounted under drive letter E
if ($Aspect -eq "B9" -or $Aspect -eq "B9.M1" -or $Aspect -eq "B9M1" -or !$Aspect) {
    Initialize-Marking -Aspect "B9.M1" -Description "Storage: Disk is mounted under drive letter E"
    $B9M1 = Get-AspectResult -JumpIp 10.3.0.11 -Ip 172.16.3.10 -Cmd 'Get-WmiObject Win32_Volume | Select Name, FileSystem | Select-String ''ReFS'''
    Test-AspectResult -Aspect "B9.M1" -String $B9M1 -Expected "Name=E:\; FileSystem=Refs"
    Start-Marking -Aspect "B9.M1"
}

# B9.M2 - Storage: iSCSI target configured
if ($Aspect -eq "B9" -or $Aspect -eq "B9.M2" -or $Aspect -eq "B9M2" -or !$Aspect) {
    Initialize-Marking -Aspect "B9.M2" -Description "Storage: iSCSI target configured"
    $B9M2 = Get-AspectResult -JumpIp 10.3.0.11 -Ip 172.16.3.10 -Cmd 'Get-IscsiServerTarget | Select InitiatorIds, LunMappings | Format-Table -AutoSize'
    Test-AspectResult -Aspect "B9.M2" -String $B9M2 -Expected "Target exist with LunMapping to VHD"
    Start-Marking -Aspect "B9.M2"
}

# B9.M3 - Storage: iSCSI virtual disk created
if ($Aspect -eq "B9" -or $Aspect -eq "B9.M3" -or $Aspect -eq "B9M3" -or !$Aspect) {
    Initialize-Marking -Aspect "B9.M3" -Description "Storage: iSCSI virtual disk created"
    $B9M3 = Get-AspectResult -JumpIp 10.3.0.11 -Ip 172.16.3.10 -Cmd 'Test-Path E:\iSCSIVirtualDisks\ES2023-VM.vhdx'
    Test-AspectResult -Aspect "B9.M3" -String $B9M3 -Expected "TRUE"
    Start-Marking -Aspect "B9.M3"
}

# B10.M1 - Web: IIS Certificate has been issued by "DK-Server" template
if ($Aspect -eq "B10.M1" -or $Aspect -eq "B10.M1" -or $Aspect -eq "B10M1" -or !$Aspect) {
    Initialize-Marking -Aspect "B10.M1" -Description "Web: IIS Certificate has been issued by 'DK-Server' template"
    $B10M1 = Get-AspectResult -Ip 10.3.0.11 -Cmd 'Import-Module WebAdministration; $thumbprint = (Get-ChildItem IIS:SSLBindings | Where { $_.Port -Like 443 }).Thumbprint; $cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where { $_.Thumbprint -eq $thumbprint }; ($cert.Extensions | Where { $_.Oid.FriendlyName -eq ''Certificate Template Information'' }).Format(0)'
    Test-AspectResult -Aspect "B10.M1" -String $B10M1 -Expected "Template=PL-Server"
    Start-Marking -Aspect "B10.M1"
}

# B10.M2 - Storage: iSCSI disk configured correctly
if ($Aspect -eq "B10" -or $Aspect -eq "B10.M2" -or $Aspect -eq "B10M1" -or !$Aspect) {
    Initialize-Marking -Aspect "B10.M2" -Description "Storage: iSCSI disk configured correctly"
    $B10M2 = Get-AspectResult -Ip 10.3.0.11 -Cmd 'Get-IscsiTarget'
    Test-AspectResult -Aspect "B10.M2" -String $B10M2 -Expected "iSCSI disk is connected to dk-storage"
    Start-Marking -Aspect "B10.M2"
}

# B10.M3 - Cluster: Configured as DK-CLUSTER
if ($Aspect -eq "B10" -or $Aspect -eq "B10.M3" -or $Aspect -eq "B10M2" -or !$Aspect) {
    Initialize-Marking -Aspect "B10.M3" -Description "Cluster: Configured as DK-CLUSTER"
    $B10M3 = Get-AspectResult -Ip 10.3.0.11 -Cmd 'Get-Cluster'
    Test-AspectResult -Aspect "B10.M3" -String $B10M3 -Expected "DK-CLUSTER"
    Start-Marking -Aspect "B10.M3"
}

# B10.M4 - Cluster: Quorum witness configured
if ($Aspect -eq "B10" -or $Aspect -eq "B10.M4" -or $Aspect -eq "B10M3" -or !$Aspect) {
    Initialize-Marking -Aspect "B10.M4" -Description "Cluster: Quorum witness configured"
    $B10M4 = Get-AspectResult -Ip 10.3.0.11 -Cmd 'Get-ClusterResource | Where { $_.ResourceType -Like ''File Share Witness'' } | Get-ClusterParameter ''SharePath'''
    Test-AspectResult -Aspect "B10.M4" -String $B10M4 -Expected "SharePath value: \\dk-dc.dk.skill39.wse\witness"
    Start-Marking -Aspect "B10.M4"
}

# B10.M5 - Cluster: DK-APP VM exists
if ($Aspect -eq "B10" -or $Aspect -eq "B10.M5" -or $Aspect -eq "B10M4" -or !$Aspect) {
    Initialize-Marking -Aspect "B10.M5" -Description "Cluster: DK-APP VM exists"
    $B10M5 = Get-AspectResult -Ip 10.3.0.12 -Cmd 'Get-ClusterGroup -Name Skill39-DK-Infra | Get-VM'
    Test-AspectResult -Aspect "B10.M5" -String $B10M5 -Expected "dk-app running"
    Start-Marking -Aspect "B10.M5"
}

# B10.M6 - Cluster: Live migration works
if ($Aspect -eq "B10" -or $Aspect -eq "B10.M6" -or $Aspect -eq "B10M5" -or !$Aspect) {
    Initialize-Marking -Aspect "B10.M6" -Description "Cluster: Live migration works"
    Test-AspectResult -Aspect "B10.M6" -Manual $True -Expected "`n Open Failover Cluster Manager `n Make sure that dk-app is running `n Try to live migrate VM to another node `n Live migrate it back to DK-SRV2"
    Start-Marking -Aspect "B10.M6"
}

# B11.M1 - Setup: TCP/IP configured
if ($Aspect -eq "B11" -or $Aspect -eq "B11.M1" -or $Aspect -eq "B11M1" -or !$Aspect) {
    Initialize-Marking -Aspect "B11.M1" -Description "Setup: TCP/IP configured"
    $B11M1 = Get-AspectResult -Ip 10.3.0.12 -Cmd '$username = ''dk\administrator''; $password = ConvertTo-SecureString ''Passw0rd!'' -AsPlainText -Force; $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $password; Invoke-Command -VMName (Get-VM).Name -Credential $cred { ipconfig /all }'
    Test-AspectResult -Aspect "B11.M1" -String $B11M1 -Expected "`n IP - 10.3.0.254 `n Mask - 255.255.255.0 `n Gateway - 10.3.0.254 `n DNS Server - 10.3.0.1"
    Start-Marking -Aspect "B11.M1"
}

# B11.M2 - Setup: Joined to dk.skill39.wse domain
if ($Aspect -eq "B11" -or $Aspect -eq "B11.M2" -or $Aspect -eq "B11M2" -or !$Aspect) {
    Initialize-Marking -Aspect "B11.M2" -Description "Setup: Joined to dk.skill39.wse domain"
    $B11M2 = Get-AspectResult -Ip 10.3.0.12 -Cmd '$username = ''dk\administrator''; $password = ConvertTo-SecureString ''Passw0rd!'' -AsPlainText -Force; $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $password; Invoke-Command -VMName (Get-VM).Name -Credential $cred { (Get-WmiObject -Class Win32_ComputerSystem).Domain }'
    Test-AspectResult -Aspect "B11.M2" -String $B11M2 -Expected "dk.skill39.wse"
    Start-Marking -Aspect "B11.M2"
}

# B11.M3 - Setup: Time Format is Danish; Key Map is US
if ($Aspect -eq "B11" -or $Aspect -eq "B11.M3" -or $Aspect -eq "B11M3" -or !$Aspect) {
    Initialize-Marking -Aspect "B11.M3" -Description "Setup: Time Format is Danish; Key Map is US"
    $B11M3 = Get-AspectResult -Ip 10.3.0.12 -Cmd '$username = ''dk\administrator''; $password = ConvertTo-SecureString ''Passw0rd!'' -AsPlainText -Force; $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $password; Invoke-Command -VMName (Get-VM).Name -Credential $cred { (Get-TimeZone).DisplayName; (Get-Culture).Name }'
    Test-AspectResult -Aspect "B11.M3" -String $B11M3 -Expected "Copenhagen, en-US"
    Start-Marking -Aspect "B11.M3"
}

# B12.M1 - Web: User can access http://web.dk.skill39.wse
if ($Aspect -eq "B12" -or $Aspect -eq "B12.M1" -or $Aspect -eq "B12M1" -or !$Aspect) {
    Initialize-Marking -Aspect "B12.M1" -Description "Web: User can access http://web.dk.skill39.wse"
    Test-AspectResult -Manual $True -Aspect "B12.M1" -Expected "DK-CLIENT: Try to log-in with user account into web portal at http://web.dk.skill39.wse"
    Start-Marking -Aspect "B12.M1"
}

# B12.M2 - Web: User can access http://web.dk.skill39.wse
if ($Aspect -eq "B12" -or $Aspect -eq "B12.M2" -or $Aspect -eq "B12M2" -or !$Aspect) {
    Initialize-Marking -Aspect "B12.M2" -Description "Web: User can access https://web.dk.skill39.wse"
    Test-AspectResult -Manual $True -Aspect "B12.M2" -Expected "DK-CLIENT: Try to log-in with user account into web portal at https://web.dk.skill39.wse"
    Start-Marking -Aspect "B12.M2"
}

# B12.M3 - GPO: Detailed status messages are presented
if ($Aspect -eq "B12" -or $Aspect -eq "B12.M3" -or $Aspect -eq "B12M3" -or !$Aspect) {
    Initialize-Marking -Aspect "B12.M3" -Description "GPO: Detailed status messages are presented"
    $B12M3 = Get-AspectResult -Ip "DK-CLIENT.DK.SKILL39.WSE" -User "dk\administrator" -Cmd '(Get-ItemProperty ''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'').VerboseStatus'
    Test-AspectResult -Aspect "B12.M3" -String $B12M3 -Expected "1"
    Start-Marking -Aspect "B12.M3"
}

# B12.M4 - RDS: Notepad is accessible for DK Experts
if ($Aspect -eq "B12" -or $Aspect -eq "B12.M4" -or $Aspect -eq "B12M4" -or !$Aspect) {
    Initialize-Marking -Aspect "B7.M10" -Description "RDS: Notepad is accessible for DK Experts"
    Test-AspectResult -Manual $True -Aspect "B12.M4" -Expected "`n Access https://rds.dk.skill39.wse/RDWeb `n Log-in with Experts role account and try to open Notepad `n Wordprad is not avalable in RDWeb `n"
    Start-Marking -Aspect "B12.M4"
}
