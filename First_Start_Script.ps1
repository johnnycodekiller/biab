# Mount Drive on deploy share

if (test-path -path "deploy:"){

    write-output "exists"
}
else {
    New-PSDrive -Name 'deploy1' -PSProvider 'Filesystem' -Root "\\192.168.10.21\Deploy\Deploy Scripts\DEV"
}



#Gets MAC and runs appropriate script


$mac = Get-NetAdapter



if ($mac.MacAddress -eq '3C-52-82-6C-1F-C0') {
    write-output "its me"


}

elseif($mac.MacAddress -eq '00-50-56-90-b9-01'){
    write-output "RUN AD"
    & "deploy1:\DomainControllerBuild.v2.ps1"
}
elseif($mac.MacAddress -eq '00-50-56-90-b9-02'){
    write-output "RUN CertSRV"
    & "deploy1:\CertificateAuthBuild.v2.ps1"
}
elseif($mac.MacAddress -eq '00-50-56-90-b9-03'){
    write-output "RUN SQL"
    & "deploy1:\SQLBuild.v2.ps1"
}
elseif($mac.MacAddress -eq '00-50-56-90-b9-04'){
    write-output "RUN SP"
    & "deploy1:\SharePointFarmBuild.v2.ps1"
}
