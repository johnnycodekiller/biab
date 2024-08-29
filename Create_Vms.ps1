# Mount Drive on deploy share

if (test-path -path "deploy:"){

    write-output "exists"
}
else {
    New-PSDrive -Name 'deploy' -PSProvider 'Filesystem' -Root "\\192.168.10.21\Deploy\Deploy Scripts\DEV\reference-files"
}


#check for old installation files and delete if exist.

if (test-path -Path "deploy:\*") {

    write-output "Previous Installation files exist. Removing......."
    try {
        rm 'deploy:\*'
    }
    catch{
    
    
    }
}
else {


}


<# Parameters for script #>
$Domain = read-host ('Please enter the FQDN')

$Credentialusrnm = read-host ('please enter the FULL domain admin username EX: DOMAIN\administrator')
$Credentialusrpwd = read-host ('Please enter domain admin password')

$SafeModeUsername = read-host ('Please enter domain safe mode username')    
$SafeModePassword = read-host ('Please enter domain safe mode password')
    
$ServiceAccountPassword = read-host ('Please enter Service Account password')

<# Check for existing encrypted files #>

<# Encrypt to txt file #>

$domain | out-file "deploy:\domain.txt"
$stringitup = "$Credentialusrnm,$Credentialusrpwd" | out-file "deploy:\dacredz.txt"


$stringitup = "$SafeModeUsername,$SafeModePassword" | out-file "deploy:\localadcredz.txt"

$ServiceAccountPassword |out-file "deploy:\servicecredz.txt"



# Connect to vcenter and build VMs.


write-output "Connecting to Vcenter"

try { connect-viserver -server 150vlabcb001 -user 'administrator@vsphere.local' -password "1qaz2wsx!QAZ@WSX" }
catch {"Could not Connect to Vsphere"}
write-output "connected"

write-output "Looking for template"
$template = get-template -name 'srvr2016_WITHDSC'
write-output $template  "template Found"

write-output "Creating VMs from template"
try{
    $VMS = @('ADsrv','00:50:56:90:b9:01','member'),@('certsrv','00:50:56:90:b9:02','member'),@('sqlsrv','00:50:56:90:b9:03','sql'), @('shpntsrv', '00:50:56:90:b9:04','sharepoint')

    foreach ($VM in $VMS)
    {

        $scriptblock = {
                                connect-viserver -server 150vlabcb001 -user 'administrator@vsphere.local' -password '1qaz2wsx!QAZ@WSX'

                                If($args[2] -eq 'member'){
                                    
                                    new-vm -name $args[0] -template 'srvr2016_WITHDSC' -VMhost '192.168.10.11' -datastore 'DS2-1' -location 'DEV_VMs' -OScustomizationSpec 'Windows Changes with script'  | get-networkadapter | set-networkadapter -Macaddress $args[1] -confirm:$false
                                
                                }
                                
                                elseif($args[2] -eq 'sql'){
                                
                                new-vm -name $args[0] -template 'srvr2016_2hd_withDSC' -VMhost '192.168.10.11' -datastore 'DS2-1' -location 'DEV_VMs' -OScustomizationSpec 'Windows Changes with script'  | get-networkadapter | set-networkadapter -Macaddress $args[1] -confirm:$false

                                }

                                elseif($args[2] -eq 'sharepoint'){
                                
                                new-vm -name $args[0] -template 'srvr2016_2hd_withDSC' -VMhost '192.168.10.11' -datastore 'DS2-1' -location 'DEV_VMs' -OScustomizationSpec 'Windows Changes with script'  | get-networkadapter | set-networkadapter -Macaddress $args[1] -confirm:$false
                                
                                }
                                
                                #new-vm -name $args[0] -template 'srvr2016_WITHDSC' -VMhost '192.168.10.11' -datastore 'DS2-1' -location 'DEV_VMs' -OScustomizationSpec 'Windows Changes'  | get-networkadapter | set-networkadapter -Macaddress $args[1] -confirm:$false 
                                start-vm -VM $args[0]
                         }

        $job = start-job -ScriptBlock $scriptblock -ArgumentList @($VM[0],$VM[1],$VM[2])
        write-output $VM[0] "created"  

    }
}

catch {"Couldnt create all VMs correctly"}

