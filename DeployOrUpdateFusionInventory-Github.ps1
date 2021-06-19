#******************************************
#*DeployOrUpdateFusionAgent by            *
#*v0.5 20210619                           *
#*Author: Roberto Jose Etcheverry Romero  *
#******************************************

If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
  # Relaunch as an elevated process:
  Start-Process powershell.exe  "-ExecutionPolicy Bypass -File",('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs
  exit
}
Write-Output  "******************************************
*DeployOrUpdateFusionAgent by            *
*v0.5 20210619                           *
*Author: Roberto Jose Etcheverry Romero  *
******************************************"
# Now running elevated so launch the script:

# Variable definition:
# Major.Minor.Release
$SetupVersion = "2.6"
# Download source
$SetupLocation =  "https://github.com/fusioninventory/fusioninventory-agent/releases/download/" + $SetupVersion
# Install Parameters, check the documentation for the list of options
$SetupOptions = "/acceptlicense /runnow /add-firewall-exception /execmode=Service /server='https://example.com/plugins/fusioninventory/' /installdir='C:\Program Files\FusionInventory-Agent' /logger='File' /ca-cert-dir='C:\Program Files\FusionInventory-Agent\certs\' /S"
# Filename parameter. You should not need to modify this ever.
$SetupFile = "fusioninventory-agent_windows-Auto_" + $SetupVersion + ".exe"
# Enable or disable GLPI Certificate download and installation
$GLPIServerCertDownload = 1
# Location of the GLPI Server certificates, if needed
$GLPIServerCertSource1 = "https://example.com/certs/cert1"
$GLPIServerCertSource2 = "https://example.com/certs/cert2"
# Install location for the GLPI Server certificates
$GLPIServerCertDestination1 = "C:\Program Files\FusionInventory-Agent\certs\cert1"
$GLPIServerCertDestination2 = "C:\Program Files\FusionInventory-Agent\certs\cert2"

# DO NOT EDIT BELOW THIS LINE
# Function definition zone
function Get-RERegistryKeyValue
{
  param(
        [string] $PathToKey,
        [string] $Name
  )
  # Search for currently installed version
    try
    {
      $CurrentVer = Get-ItemPropertyValue -Path $PathToKey -Name $Name -ErrorAction:Stop
      return $CurrentVer
    }
    Catch [System.Management.Automation.PSArgumentException],[System.Management.Automation.ItemNotFoundException]
    {
      return "0"
    }
}

# Script start
$CurrentVer = "0"
# Check architecture and currently installed agent's level
if ('AMD64' -eq $env:PROCESSOR_ARCHITECTURE)
  {
    Write-Output "Detected x64 architecture."
    $SetupFile = $SetupFile -replace "-Auto_", "-x64_"
    $CurrentVer = Get-RERegistryKeyValue -PathToKey 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FusionInventory-Agent\' -Name 'DisplayVersion'
    if ("0" -eq $CurrentVer)
    {
      $CurrentVer = Get-RERegistryKeyValue -PathToKey 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\FusionInventory Agent\' -Name 'DisplayVersion'
      if ("0" -eq $CurrentVer)
      {
        $CurrentVer = Get-RERegistryKeyValue -PathToKey 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\FusionInventory-Agent\' -Name 'DisplayVersion'
      }
    }
  }
elseif ('x86' -eq $env:PROCESSOR_ARCHITECTURE)
  {
    Write-Output "Detected x86 architecture."
    $SetupFile = $SetupFile -replace "-Auto_", "-x86_"
    $CurrentVer = Get-RERegistryKeyValue -PathToKey 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FusionInventory Agent\' -Name 'DisplayVersion'
    if (0 -eq $CurrentVer)
    {
      $CurrentVer = Get-RERegistryKeyValue -PathToKey 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FusionInventory-Agent\' -Name 'DisplayVersion'
    }
  }
else
{
  # Unsupported arch
  Write-Output "$env:PROCESSOR_ARCHITECTURE is not a supported architecture."
  # Wait a bit to show output if running manually, but allow script completion if automated
  Start-Sleep -Seconds 30
  return
}

# Check if update is needed
if ($SetupVersion -le $CurrentVer)
{
  # If the required version is already installed
  Write-Output "FusionInventory Agent version $CurrentVer is already installed."

  Start-Sleep -Seconds 30
  return
}

# Set TLS 1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;

# Download the agent's installer
Write-Output "FusionInventory Agent: $SetupVersion for $env:PROCESSOR_ARCHITECTURE will be downloaded and installed."
try
{
  Invoke-WebRequest -Uri $($SetupLocation + '/' + $SetupFile) -OutFile $($env:TEMP + '\' + $SetupFile) -ErrorAction:Stop
  Write-Output "Download completed."
}
Catch
{
  Write-Output "Error downloading package. Exiting now."

  Start-Sleep -Seconds 30
  return
}
# If installed, stop current agent
if ("0" -lt $CurrentVer)
{
  Stop-Process -Name "fusioninventory-agent" -Force
}
# Download the GLPI server's certificates if enabled and needed
if (($GLPIServerCertDownload)-and(-not(Test-Path -Path $GLPIServerCertDestination1 -PathType Leaf)))
{
  New-Item -ItemType "directory" -Path "C:\Program Files\FusionInventory-Agent\certs\"
  try
  {
    Write-Output "Starting GLPI Server certificates download."
    Invoke-WebRequest -Uri $GLPIServerCertSource1 -OutFile $GLPIServerCertDestination1 -ErrorAction:Stop
    Invoke-WebRequest -Uri $GLPIServerCertSource2 -OutFile $GLPIServerCertDestination2 -ErrorAction:Stop
    Write-Output "Certificates download completed."
  }
  Catch
  {
    Write-Output "Error downloading certificates. Exiting now."

    Start-Sleep -Seconds 30
    return
  }
}
# Start installation
try
{
  Write-Output "Starting installation."
  Start-Process -wait -FilePath $($env:TEMP + '\' + $SetupFile) -ArgumentList  $SetupOptions -ErrorAction:Stop
  Write-Output "Installation completed."
}
Catch
{
  Write-Output "Error installing package. Exiting now."
  Remove-Item -Path $($env:TEMP + '\' + $SetupFile)

  Start-Sleep -Seconds 30
  return
}
# Delete temp file and exit
Remove-Item -Path $($env:TEMP + '\' + $SetupFile)

Start-Sleep -Seconds 30
