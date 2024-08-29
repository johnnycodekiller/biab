

# Mount Drive on deploy share

if (test-path -path "deploy:"){

    write-output "exists"
}
else {
    New-PSDrive -Name 'deploy' -PSProvider 'Filesystem' -Root "\\192.168.10.21\Deploy\Deploy Scripts\DEV\reference-files"
}




    $key = [byte]1..16
    $credarray = get-content "deploy:\dacredz.txt"
    $credarraysplit = $credarray.split(',')
    $Credentialusername = $credarraysplit[0]
    $Credentialpassword = convertto-securestring -string $credarraysplit[1] -asplaintext -force
  
    $Credential = new-object -typename system.management.automation.pscredential -argumentlist $Credentialusername,$Credentialpassword




    $Credential = Get-Credential -UserName 'administrator' -Message "New Domain Admin User Name and Password"
    
	$SafeModePassword = $Credential
    $ServiceAccountPassword = $Credential







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

$Credentialusrnm = read-host ('please enter domain admin username')
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



$domainfromtxt = get-content deploy:\domain.txt
$domainfromtxtsplit = $domainfromtxt.split('.')



$Credential = new-object system.management.automation.pscredential -argumentlist $credentialusername, $credentialpassword




	
<# Account Credentials from file#>


    $key = [byte]1..16
    $credarray = get-content "deploy:\dacredz.txt"
    $credarraysplit = $credarray.split('`n'
    $credarray[0]
    $credarray[1]
    $Credentialusername = $credarray[0]
    $Credentialpassword = convertf-securestring -key $key $credarray[1]
