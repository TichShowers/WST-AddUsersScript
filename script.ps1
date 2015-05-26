[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True,Position=1)]
    [string]$fileName,
    [Parameter(Mandatory=$False)]
    [bool]$forceChangePassword = $true
)

Write-Output "Importing CSV"

$People = Import-Csv $fileName

Write-Output "Creating OU"
$OUName = [System.IO.Path]::GetFileNameWithoutExtension($fileName)
$DomainName = (Get-ADDomain).DistinguishedName
$NewOU = New-ADOrganizationalUnit -Name $OUName -Path $DomainName -ProtectedFromAccidentalDeletion $false -PassThru
$OUPath = $NewOU.DistinguishedName

Write-Output "Creating Security Group and Password Policy"

$OUPolicy = New-ADFineGrainedPasswordPolicy -Name ($OUName + "-PasswordPolicy") `
            -ProtectedFromAccidentalDeletion $false `
            -PassThru `
            -ComplexityEnabled $false `
            -PasswordHistoryCount 0 `
            -MinPasswordLength 0 `
            -MinPasswordAge "0" `
            -MaxPasswordAge "0" `
            -Precedence 1


foreach($Person in $People) {
    Write-Output "Creating Folder for $($Person.user_name)" 

    $Folder = Join-Path -Path "C:\HomeFolders" -ChildPath $Person.user_name 

    New-Item -Path $Folder -ItemType directory

    Write-Output "Creating user $($Person.user_name)"

	$User = New-ADUser $Person.user_name `
            -GivenName $Person.first_name `
            -Surname $Person.last_name `
            -DisplayName ($Person.first_name + " " + $Person.last_name) `
            -Path $OUPath ` `
            -ChangePasswordAtLogon $forceChangePassword `
            -accountPassword (ConvertTo-SecureString -AsPlainText 'Friday13th!' -Force) `
            -PassThru `
            -enabled $true `
            -homedrive "H" `
            -homedirectory "\\$($env:computername)\HomeFolders\$($Person.user_name)"
    
    Write-Output "Setting password and security group for $($Person.user_name)"

    Add-ADFineGrainedPasswordPolicySubject -Subjects $User -Identity $OUPolicy

    Set-ADAccountPassword -Identity $User.Name -NewPassword (ConvertTo-SecureString -AsPlainText $Person.birth_date -Force) -OldPassword (ConvertTo-SecureString -AsPlainText 'Friday13th!' -Force)

    Write-Output "Changing HomeFolder ACL for $($Person.user_name)"

    $colRights = [System.Security.AccessControl.FileSystemRights]"FullControl" 

    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit 
    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::InheritOnly 

    $objType =[System.Security.AccessControl.AccessControlType]::Allow 

    $objUser = New-Object System.Security.Principal.NTAccount($user.samaccountname) 

    $objACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
        ($objUser, $colRights, $InheritanceFlag, $PropagationFlag, $objType) 

    $objACL = Get-ACL $Folder
    $objACL.AddAccessRule($objACE) 

    $objACL | Set-ACL -Path $Folder
}
