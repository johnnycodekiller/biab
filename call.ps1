# Mount Drive on deploy share

if (test-path -path "deploy:"){

    write-output "exists"
}
else {
    New-PSDrive -Name 'deploy1' -PSProvider 'Filesystem' -Root "\\192.168.10.21\Deploy\Deploy Scripts\DEV"
}


& "deploy1:\First_Start_Script.ps1"