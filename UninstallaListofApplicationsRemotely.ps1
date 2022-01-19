#Enter the list of servernames

$serverList = @"
#Servername1
#Servername2
#Servername3
"@ -split "`r`n" | ForEach-Object Trim


Invoke-Command $serverList {

#This part looks at all installed software installed on a computer then puts the info in $InstalledSoftware

$InstalledSoftware = & {
    Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
    Get-ChildItem HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall
} |
    ForEach-Object {
        $properties = Get-ItemProperty -Path $_.PSPath
        if (!$properties.DisplayName) { return }
        $result = [ordered]@{}
        $result.ComputerName = $env:COMPUTERNAME
        $result.Name = try { $properties.DisplayName.Trim() } catch { $null }
        $result.Version = try { $properties.DisplayVersion.Trim() } catch { $null }
        $result.ProductId = if ($properties.WindowsInstaller -eq 1 -and $properties.UninstallString -match "(\{.+?\})")
            { $Matches[1] } else { $null }
        $result.Bit = 64
        $result.Publisher = try { $properties.Publisher.Trim() } catch { $null }
        $result.InstallSource = try { $properties.InstallSource.Trim() } catch { $null }
        $result.InstallDate = try { [DateTime]::ParseExact($properties.InstallDate, 'yyyyMMdd', $null) } catch { }
        if ($_.PSPath -match 'Wow6432Node') { $result.Bit = 32 }
        [pscustomobject]$result
    } |
    Sort-Object Name

#This part will list all installed software in Gridview
$InstalledSoftware | Out-GridView


#This part will then ask the user to enter in the common application name that it will match against
$ApplicationName = Read-Host -Prompt "Enter in application name"

$UninstallList = $InstalledSoftware |
    Where-Object Name -match $ApplicationName

#Shows the list of Installed Products that you want uninstalled based on what you what you provided against userinput for its match 
$UninstallList

#This last part will uninstall everything that it was matched too. 

$UninstallList |
    ForEach-Object {
        msiexec /qn /passive /x $_.ProductId
    }
}