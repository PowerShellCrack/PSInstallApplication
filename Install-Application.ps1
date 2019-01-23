<#
.SYNOPSIS
	This script performs the installation or uninstallation of an application(s) using an XML
.DESCRIPTION

.PARAMETER SettingsName
	XML File to parse for application rules. Default is: Settings.xml
.PARAMETER InstallerArg
	Specifies whether the installation should be run in Interactive, Silent, or NonInteractive mode. Default is: Interactive. Options: Interactive = Shows dialogs, Silent = No dialogs, NonInteractive = Very silent, i.e. no blocking apps. NonInteractive mode is automatically set if it is detected that the process is not user interactive.
.PARAMETER SwitchArg
	Allows the 3010 return code (requires restart) to be passed back to the parent process (e.g. SCCM) if detected from an installation. If 3010 is passed back to SCCM, a reboot prompt will be triggered.
.PARAMETER DetectionArg
	Changes to "user install mode" and back to "user execute mode" for installing/uninstalling applications for Remote Destkop Session Hosts/Citrix servers.
.PARAMETER DisableLogging
	Disables logging to file for the script. Default is: $false.
.EXAMPLE
	Install-Application.ps1
.EXAMPLE
	Install-Application.ps1 -SettingsName 7Zip.xml
.EXAMPLE
	Deploy-Application.ps1 -InstallerArg "/qn"
.EXAMPLE
	Install-Application.ps1 -DeploymentType Uninstall
#>

Param (
    [Parameter(Mandatory=$false)]
    [string]$SettingsName = "Settings.xml",
    [Parameter(Mandatory=$false)]
    [string]$InstallerArg,
    [Parameter(Mandatory=$false)]
    [string]$SwitchArg,
    [Parameter(Mandatory=$false)]
    [string]$DetectionArg
)

##*===========================================================================
##* FUNCTIONS
##*===========================================================================
#time-lapse formatter
Function Format-ElapsedTime($ts) {
    $elapsedTime = ""
    if ( $ts.Minutes -gt 0 ){$elapsedTime = [string]::Format( "{0:00} min. {1:00}.{2:00} sec.", $ts.Minutes, $ts.Seconds, $ts.Milliseconds / 10 );}
    else{$elapsedTime = [string]::Format( "{0:00}.{1:00} sec.", $ts.Seconds, $ts.Milliseconds / 10 );}
    if ($ts.Hours -eq 0 -and $ts.Minutes -eq 0 -and $ts.Seconds -eq 0){$elapsedTime = [string]::Format("{0:00} ms.", $ts.Milliseconds);}
    if ($ts.Milliseconds -eq 0){$elapsedTime = [string]::Format("{0} ms", $ts.TotalMilliseconds);}
    return $elapsedTime
}

Function Format-DatePrefix{
    [string]$LogTime = (Get-Date -Format 'HH:mm:ss.fff').ToString()
	[string]$LogDate = (Get-Date -Format 'MM-dd-yyyy').ToString()
    $CombinedDateTime = "$LogDate $LogTime"
    return ($LogDate + " " + $LogTime)
}

Function Write-LogEntry {
    param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        [Parameter(Mandatory=$false,Position=2)]
		[ValidateNotNull()]
		[string]$Source = '',
        [parameter(Mandatory=$false)]
        [ValidateSet(0,1,2,3,4)]
        [int16]$Severity,

        [parameter(Mandatory=$false, HelpMessage="Name of the log file that the entry will written to.")]
        [ValidateNotNullOrEmpty()]
        [string]$OutputLogFile = $Global:LogFilePath,

        [parameter(Mandatory=$false)]
        [switch]$Outhost
    )
    ## Get the name of this function
    [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

    ## Format Log date entry
    $DateEntry = Format-DatePrefix

    [string]$LogTime = (Get-Date -Format 'HH:mm:ss.fff').ToString()
	[string]$LogDate = (Get-Date -Format 'MM-dd-yyyy').ToString()
	[int32]$script:LogTimeZoneBias = [timezone]::CurrentTimeZone.GetUtcOffset([datetime]::Now).TotalMinutes
	[string]$LogTimePlusBias = $LogTime + $script:LogTimeZoneBias
    #  Get the file name of the source script

    Try {
	    If ($script:MyInvocation.Value.ScriptName) {
		    [string]$ScriptSource = Split-Path -Path $script:MyInvocation.Value.ScriptName -Leaf -ErrorAction 'Stop'
	    }
	    Else {
		    [string]$ScriptSource = Split-Path -Path $script:MyInvocation.MyCommand.Definition -Leaf -ErrorAction 'Stop'
	    }
    }
    Catch {
	    $ScriptSource = ''
    }
    
    
    If(!$Severity){$Severity = 1}
    $LogFormat = "<![LOG[$Message]LOG]!>" + "<time=`"$LogTimePlusBias`" " + "date=`"$LogDate`" " + "component=`"$ScriptSource`" " + "context=`"$([Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + "type=`"$Severity`" " + "thread=`"$PID`" " + "file=`"$ScriptSource`">"
    
    # Add value to log file
    try {
        Out-File -InputObject $LogFormat -Append -NoClobber -Encoding Default -FilePath $OutputLogFile -ErrorAction Stop
    }
    catch {
        Write-Host ("[{0}] [{1}] :: Unable to append log entry to [{1}], error: {2}" -f $DateEntry,$ScriptSource,$OutputLogFile,$_.Exception.ErrorMessage) -ForegroundColor Red
    }
    If($Outhost){
        If($Source){
            $OutputMsg = ("[{0}] [{1}] :: {2}" -f $DateEntry,$Source,$Message)
        }
        Else{
            $OutputMsg = ("[{0}] [{1}] :: {2}" -f $DateEntry,$ScriptSource,$Message)
        }

        Switch($Severity){
            0       {Write-Host $OutputMsg -ForegroundColor Green}
            1       {Write-Host $OutputMsg -ForegroundColor Gray}
            2       {Write-Warning $OutputMsg}
            3       {Write-Host $OutputMsg -ForegroundColor Red}
            4       {If($Global:Verbose){Write-Verbose $OutputMsg}}
            default {Write-Host $OutputMsg}
        }
    }
}


Function Get-RegistryRoot($RegPath){
    $RegRoot = $RegPath.Split("\")[0]
    Switch($RegRoot){
        HKEY_LOCAL_MACHINE {$RegProperty = 'HKLM:'}
        HKEY_CURRENT_USER {$RegProperty = 'HKCU:'}
    }
    return $RegProperty
}

Function Get-FriendlyMsiExecMsg($exit) {
    Switch($exit){
      0    {$meaning = 'ERROR_SUCCESS'; $description = 'The action completed successfully.'}
      13   {$meaning = 'ERROR_INVALID_DATA'; $description = 'The data is invalid.'}
      87   {$meaning = 'ERROR_INVALID_PARAMETER'; $description = 'One of the parameters was invalid.'}
      120  {$meaning = 'ERROR_CALL_NOT_IMPLEMENTED'; $description = 'This value is returned when a custom action attempts to call a function that cannot be called from custom actions. The function returns the value ERROR_CALL_NOT_IMPLEMENTED. Available beginning with Windows Installer version 3.0.'}
      1259 {$meaning = 'ERROR_APPHELP_BLOCK'; $description = 'If Windows Installer determines a product may be incompatible with the current operating system, it displays a dialog box informing the user and asking whether to try to install anyway. This error code is returned if the user chooses not to try the installation.'}
      1601 {$meaning = 'ERROR_INSTALL_SERVICE_FAILURE'; $description = 'The Windows Installer service could not be accessed. Contact your support personnel to verify that the Windows Installer service is properly registered.'}
      1602 {$meaning = 'ERROR_INSTALL_USEREXIT'; $description = 'The user cancels installation.'}
      1603 {$meaning = 'ERROR_INSTALL_FAILURE'; $description = 'A fatal error occurred during installation.'}
      1604 {$meaning = 'ERROR_INSTALL_SUSPEND'; $description = 'Installation suspended, incomplete.'}
      1605 {$meaning = 'ERROR_UNKNOWN_PRODUCT'; $description = 'This action is only valid for products that are currently installed.'}
      1606 {$meaning = 'ERROR_UNKNOWN_FEATURE'; $description = 'The feature identifier is not registered.'}
      1607 {$meaning = 'ERROR_UNKNOWN_COMPONENT'; $description = 'The component identifier is not registered.'}
      1608 {$meaning = 'ERROR_UNKNOWN_PROPERTY'; $description = 'This is an unknown property.'}
      1609 {$meaning = 'ERROR_INVALID_HANDLE_STATE'; $description = 'The handle is in an invalid state.'}
      1610 {$meaning = 'ERROR_BAD_CONFIGURATION'; $description = 'The configuration data for this product is corrupt. Contact your support personnel.'}
      1611 {$meaning = 'ERROR_INDEX_ABSENT'; $description = 'The component qualifier not present.'}
      1612 {$meaning = 'ERROR_INSTALL_SOURCE_ABSENT'; $description = 'The installation source for this product is not available. Verify that the source exists and that you can access it.'}
      1613 {$meaning = 'ERROR_INSTALL_PACKAGE_VERSION'; $description = 'This installation package cannot be installed by the Windows Installer service. You must install a Windows service pack that contains a newer version of the Windows Installer service.'}
      1614 {$meaning = 'ERROR_PRODUCT_UNINSTALLED'; $description = 'The product is uninstalled.'}
      1615 {$meaning = 'ERROR_BAD_QUERY_SYNTAX'; $description = 'The SQL query syntax is invalid or unsupported.'}
      1616 {$meaning = 'ERROR_INVALID_FIELD'; $description = 'The record field does not exist.'}
      1618 {$meaning = 'ERROR_INSTALL_ALREADY_RUNNING'; $description = 'Another installation is already in progress. Complete that installation before proceeding with this install.'}
      1619 {$meaning = 'ERROR_INSTALL_PACKAGE_OPEN_FAILED'; $description = 'This installation package could not be opened. Verify that the package exists and is accessible, or contact the application vendor to verify that this is a valid Windows Installer package.'}
      1620 {$meaning = 'ERROR_INSTALL_PACKAGE_INVALID'; $description = 'This installation package could not be opened. Contact the application vendor to verify that this is a valid Windows Installer package.'}
      1621 {$meaning = 'ERROR_INSTALL_UI_FAILURE'; $description = 'There was an error starting the Windows Installer service user interface. Contact your support personnel.'}
      1622 {$meaning = 'ERROR_INSTALL_LOG_FAILURE'; $description = 'There was an error opening installation log file. Verify that the specified log file location exists and is writable.'}
      1623 {$meaning = 'ERROR_INSTALL_LANGUAGE_UNSUPPORTED'; $description = 'This language of this installation package is not supported by your system.'}
      1624 {$meaning = 'ERROR_INSTALL_TRANSFORM_FAILURE'; $description = 'There was an error applying transforms. Verify that the specified transform paths are valid.'}
      1625 {$meaning = 'ERROR_INSTALL_PACKAGE_REJECTED'; $description = 'This installation is forbidden by system policy. Contact your system administrator.'}
      1626 {$meaning = 'ERROR_FUNCTION_NOT_CALLED'; $description = 'The function could not be executed.'}
      1627 {$meaning = 'ERROR_FUNCTION_FAILED'; $description = 'The function failed during execution.'}
      1628 {$meaning = 'ERROR_INVALID_TABLE'; $description = 'An invalid or unknown table was specified.'}
      1629 {$meaning = 'ERROR_DATATYPE_MISMATCH'; $description = 'The data supplied is the wrong type.'}
      1630 {$meaning = 'ERROR_UNSUPPORTED_TYPE'; $description = 'Data of this type is not supported.'}
      1631 {$meaning = 'ERROR_CREATE_FAILED'; $description = 'The Windows Installer service failed to start. Contact your support personnel.'}
      1632 {$meaning = 'ERROR_INSTALL_TEMP_UNWRITABLE'; $description = 'The Temp folder is either full or inaccessible. Verify that the Temp folder exists and that you can write to it.'}
      1633 {$meaning = 'ERROR_INSTALL_PLATFORM_UNSUPPORTED'; $description = 'This installation package is not supported on this platform. Contact your application vendor.'}
      1634 {$meaning = 'ERROR_INSTALL_NOTUSED'; $description = 'Component is not used on this machine.'}
      1635 {$meaning = 'ERROR_PATCH_PACKAGE_OPEN_FAILED'; $description = 'This patch package could not be opened. Verify that the patch package exists and is accessible, or contact the application vendor to verify that this is a valid Windows Installer patch package.'}
      1636 {$meaning = 'ERROR_PATCH_PACKAGE_INVALID'; $description = 'This patch package could not be opened. Contact the application vendor to verify that this is a valid Windows Installer patch package.'}
      1637 {$meaning = 'ERROR_PATCH_PACKAGE_UNSUPPORTED'; $description = 'This patch package cannot be processed by the Windows Installer service. You must install a Windows service pack that contains a newer version of the Windows Installer service.'}
      1638 {$meaning = 'ERROR_PRODUCT_VERSION'; $description = 'Another version of this product is already installed. Installation of this version cannot continue. To configure or remove the existing version of this product, use Add/Remove Programs in Control Panel.'}
      1639 {$meaning = 'ERROR_INVALID_COMMAND_LINE'; $description = 'Invalid command line argument. Consult the Windows Installer SDK for detailed command-line help.'}
      1640 {$meaning = 'ERROR_INSTALL_REMOTE_DISALLOWED'; $description = 'The current user is not permitted to perform installations from a client session of a server running the Terminal Server role service.'}
      1641 {$meaning = 'ERROR_SUCCESS_REBOOT_INITIATED'; $description = 'The installer has initiated a restart. This message is indicative of a success.'}
      1642 {$meaning = 'ERROR_PATCH_TARGET_NOT_FOUND'; $description = 'The installer cannot install the upgrade patch because the program being upgraded may be missing or the upgrade patch updates a different version of the program. Verify that the program to be upgraded exists on your computer and that you have the correct upgrade patch.'}
      1643 {$meaning = 'ERROR_PATCH_PACKAGE_REJECTED'; $description = 'The patch package is not permitted by system policy.'}
      1644 {$meaning = 'ERROR_INSTALL_TRANSFORM_REJECTED'; $description = 'One or more customizations are not permitted by system policy.'}
      1645 {$meaning = 'ERROR_INSTALL_REMOTE_PROHIBITED'; $description = 'Windows Installer does not permit installation from a Remote Desktop Connection.'}
      1646 {$meaning = 'ERROR_PATCH_REMOVAL_UNSUPPORTED'; $description = 'The patch package is not a removable patch package. Available beginning with Windows Installer version 3.0.'}
      1647 {$meaning = 'ERROR_UNKNOWN_PATCH'; $description = 'The patch is not applied to this product. Available beginning with Windows Installer version 3.0.'}
      1648 {$meaning = 'ERROR_PATCH_NO_SEQUENCE'; $description = 'No valid sequence could be found for the set of patches. Available beginning with Windows Installer version 3.0.'}
      1649 {$meaning = 'ERROR_PATCH_REMOVAL_DISALLOWED'; $description = 'Patch removal was disallowed by policy. Available beginning with Windows Installer version 3.0.'}
      1650 {$meaning = 'ERROR_INVALID_PATCH_XML'; $description = 'The XML patch data is invalid. Available beginning with Windows Installer version 3.0.'}
      1651 {$meaning = 'ERROR_PATCH_MANAGED_ADVERTISED_PRODUCT'; $description = 'Administrative user failed to apply patch for a per-user managed or a per-machine application that is in advertise state. Available beginning with Windows Installer version 3.0.'}
      1652 {$meaning = 'ERROR_INSTALL_SERVICE_SAFEBOOT'; $description = 'Windows Installer is not accessible when the computer is in Safe Mode. Exit Safe Mode and try again or try using System Restore to return your computer to a previous state. Available beginning with Windows Installer version 4.0.'}
      1653 {$meaning = 'ERROR_ROLLBACK_DISABLED'; $description = 'Could not perform a multiple-package transaction because rollback has been disabled. Multiple-Package Installations cannot run if rollback is disabled. Available beginning with Windows Installer version 4.5.'}
      1654 {$meaning = 'ERROR_INSTALL_REJECTED'; $description = 'The app that you are trying to run is not supported on this version of Windows. A Windows Installer package, patch, or transform that has not been signed by Microsoft cannot be installed on an ARM computer.'}
      3010 {$meaning = 'ERROR_SUCCESS_REBOOT_REQUIRED'; $description = 'A restart is required to complete the install. This message is indicative of a success. This does not include installs where the ForceReboot action is run.'}
    }
    return ("[{0}] {1}" -f $meaning,$description)
}


Function Scan-ExistingApplication{
<#
    based on the type of detection, process the infromation
    currently only supports types: REG or FILE or GUID
    Detection sets are only version, name and existing
#>
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("FILE", "REG", "GUID")]
        [string]$ScanMethod,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$AppPath,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$AppName,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("x64","x86","Both")]
        [string]$AppArc,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$AppValue
    )
    Begin{
        ## Get the name of this function
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

        ## Format Log date entry
        $DateEntry = Format-DatePrefix

        #determine what architecure is running for regedit path
        [boolean]$Is64Bit = [boolean]((Get-WmiObject -Class 'Win32_Processor' | Where-Object { $_.DeviceID -eq 'CPU0' } | Select-Object -ExpandProperty 'AddressWidth') -eq 64)

        #based on property specified, build filter argument scriptblock
        switch -regex ($AppName){
            "[Version]" { $Property = 'Version'}         
            "[Name]"    { $Property = 'Name'}
            "[GUID]"    { $Property = 'GUID'} 
            default     { $Property = 'All'}
        }
        #if application is set to both and runing on a 64bit system, scan both arc 
        If($AppArc -eq "Both"){$UseArc = "x86","x64"}Else{$UseArc = $AppArc}
    }
    Process {
        Try{
            $ExistingValue = $null
            #Loop on architecture if needed
            Foreach($arc in $UseArc){
                switch($ScanMethod){
                    #look for 3 properties from array
                    "REG" { 
                            $RegProperty = Get-RegistryRoot $AppPath
                            #ensure reg path follows architecture structure
                            If( ($arc -eq 'x86') -and $Is64Bit -and ($AppPath -notmatch 'WOW6432Node')){[string]$regArchSoftPath = '\SOFTWARE\WOW6432Node\'} Else { [string]$regArchSoftPath = '\SOFTWARE\' }
                            $RegPath = ($RegProperty + "\" + $AppPath.Replace('\SOFTWARE\',$regArchSoftPath))
                                   
                            #If AUTO is specified for REG type, get installer's uninstall registry key as $AppPath
                            Write-LogEntry ("Scanning registry for [{0}] with [{1}] value equal to or greater than [{2}]" -f $RegPath,$AppName,$AppValue) -Source ${CmdletName} -Severity 4 -Outhost
                            If(!$ExistingValue){
                                If($AppPath -eq '[AUTO]'){
                                #(Get-InstalledProduct -Property 'GUID' -Filter '{C8EA30FC-B20B-465E-9D8A-CDDC09EA72D4}' -Arc x86).GUID
                                Write-LogEntry ("[CMDLET] Get-InstalledProduct -Property '$Property' -Filter '$AppValue' -Arc $arc") -Source ${CmdletName} -Severity 4 -Outhost
                                $ExistingValue = (Get-InstalledProduct -Property $Property -Filter $AppValue -Arc $arc -Verbose:$Global:Verbose).$Property 
                                  
                                }
                                Else{
                                    If(Test-Path $RegPath){
                                        Write-LogEntry ("[CMDLET] Get-ItemProperty -Path '" + $RegPath + "' -Name " + $AppName) -Source ${CmdletName} -Severity 4 -Outhost
                                        $ExistingValue = Get-ItemProperty -Path $RegPath | Select -ExpandProperty $AppName -ErrorAction SilentlyContinue
                                    }
                            
                                }
                            }
                          }
                    #look for 2 properties from array
                    "FILE"{
                            #double check path to ensure proper locations
                            If( (($arc -eq 'x86') -and $Is64Bit) -and ($AppPath -notmatch '(Program Files \(x86\))')){$UpdatedAppPath = $AppPath.replace('Program Files','Program Files (x86)')}
                            If( (($arc -eq 'x86') -and $Is64Bit) -and ($AppPath -notmatch '(System32)')){$UpdatedAppPath = $AppPath.replace('System32','SysWOW64')}
                            
                            #build full path
                            $AppFullPath = Join-Path $UpdatedAppPath -ChildPath $AppName
                            Write-LogEntry ("Scanning system for file path [{0}]" -f $AppFullPath) -Source ${CmdletName}  -Severity 1 -Outhost
                            
                            # check to be sure $AppPath is a filesystem
                            If(!$ExistingValue){
                                If (Test-Path $AppFullPath){
                                    $FileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($AppFullPath).FileVersion
                                    $ExistingValue = $FileVersion.split(" ")[0].Trim()
                                }
                            }
                          }
                    #look for 1 properties from array        
                    "GUID"{
                            Write-LogEntry ("Scanning [{0}] applications for [{1}] for installed product code [{2}]" -f $arc,$AppName,$AppValue) -Source ${CmdletName}  -Severity 1 -Outhost
                            If(!$ExistingValue){
                                Write-LogEntry ("[CMDLET] Get-InstalledProduct -Property '$Property' -Filter '$AppValue' -Arc $arc") -Source ${CmdletName} -Severity 4 -Outhost
                                #eg. (Get-InstalledProduct -Property 'GUID' -Filter '{C8EA30FC-B20B-465E-9D8A-CDDC09EA72D4}' -Arc x86).GUID
                                $ExistingValue = (Get-InstalledProduct -Property $Property -Filter $AppValue -Arc $arc -Verbose:$Global:Verbose).$Property 
                            }
                          }

                }
            }

        }
        Catch{
            Write-LogEntry ("Failed to scan for existing application [{0}] using  method type [{1}]. Error: {2} " -f $AppName,$ScanMethod,$ExistingValue.Exception.ErrorMessage) -Source ${CmdletName} -Severity 3 -Outhost
            If($Global:Verbose){
                Write-LogEntry ("PASSED VARIABLES:") -Source ${CmdletName} -Severity 4 -Outhost 
                Write-LogEntry ("`$AppName='{0}'" -f $AppName) -Source ${CmdletName} -Severity 4 -Outhost 
                Write-LogEntry ("`$AppPath='{0}'" -f $AppPath) -Source ${CmdletName} -Severity 4 -Outhost 
                Write-LogEntry ("`$ScanMethod='{0}'" -f $ScanMethod) -Source ${CmdletName} -Severity 4 -Outhost 
                Write-LogEntry ("`$AppValue='{0}'" -f $AppValue) -Source ${CmdletName} -Severity 4 -Outhost
            }
            $ExistingValue = $false
        }
    }
    End {
        Write-LogEntry ("PASSED VARIABLES:") -Source ${CmdletName} -Severity 4 -Outhost 
        Write-LogEntry ("`$ExistingValue='{0}'" -f $ExistingValue) -Source ${CmdletName} -Severity 4 -Outhost
        return $ExistingValue        
    }
}

Function Get-InstalledProduct{
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Version", "Name", "GUID", "All")]
        [string]$Property,
        [parameter(Mandatory=$false)]
        [string]$Filter,
        [parameter(Mandatory=$false)]
        [ValidateSet("x64","x86")]
        [string]$Arc,
        [parameter(Mandatory=$false)]
        [switch]$WMIQuery
    )
    Begin{
        ## Get the name of this function
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

        ## Format Log date entry
        $DateEntry = Format-DatePrefix

        If($Filter){
            #based on property specified, build filter argument scriptblock
            switch($Property){
               "Version" { If($WMIQuery){$FilterArg = "Version = '$Filter'"}Else{$FilterArg = [scriptblock]::create("`$_.DisplayVersion -eq '$Filter'")} }            
               "GUID"    { If($WMIQuery){$FilterArg = "IdentifyingNumber = '$Filter'"}Else{$FilterArg = [scriptblock]::create("`$_.PSChildName -eq '$Filter'")} } 
               "Name"    { If($WMIQuery){$FilterArg = "IdentifyingNumber = '$Filter'"}Else{$FilterArg = [scriptblock]::create("`$_.PSChildName -like '$Filter*'")} } 
               "All"     { If($WMIQuery){$FilterArg = $null}Else{$FilterArg = [scriptblock]::create("`$_.PSPath -like '*'")} }
            }
            Write-LogEntry ("Filter Used: [{0}]" -f $FilterArg) -Severity 4 -Outhost 
        }
        Else{
            If($WMIQuery){$FilterArg = $null}Else{$FilterArg = [scriptblock]::create($_.PSPath -like '*')}
        }

        #determine what architecure is running for regedit path
        [boolean]$Is64Bit = [boolean]((Get-WmiObject -Class 'Win32_Processor' | Where-Object { $_.DeviceID -eq 'CPU0' } | Select-Object -ExpandProperty 'AddressWidth') -eq 64)
    }
    Process{
        Try{
            If($WMIQuery){
                Write-Warning "WMI Queries can take a long time to process and only pulls products installed by MSI. Please be patient..."
                Write-LogEntry ("[WMI] Select * From Win32_product WHERE '$FilterArg'") -Severity 4 -Outhost 
                $Products = Get-WmiObject Win32_Product -Filter $FilterArg
            }
            Else{
                If( ($Arc -eq 'x86') -and $Is64Bit){[string]$regArchPath = '\WOW6432Node\'} Else { [string]$regArchPath = '\' }
                Write-LogEntry ("[REGISTRY] [HKLM:\SOFTWARE{0}Microsoft\Windows\CurrentVersion\Uninstall] where {1}" -f $regArchPath,$FilterArg.ToString().replace('$_.','')) -Severity 4 -Outhost 
                $Products = Get-ChildItem ("HKLM:\SOFTWARE" + $regArchPath + "Microsoft\Windows\CurrentVersion\Uninstall") | ForEach-Object{ Get-ItemProperty $_.PSPath } | Where $FilterArg
            }
        }
        Catch{
            Write-LogEntry ("Failed to get product details using method type [{0}]. Error: {1} " -f $Property,$Products.Exception.ErrorMessage) -Source ${CmdletName} -Severity 3 -Outhost
            If($Global:Verbose){
                Write-LogEntry ("PASSED VARIABLES:") -Source ${CmdletName} -Severity 4 -Outhost 
                Write-LogEntry ("Failed to get product details, variables passed:") -Source ${CmdletName} -Severity 4 -Outhost
                Write-LogEntry ("`$Property='{0}'" -f $Property) -Source ${CmdletName} -Severity 4 -Outhost 
                Write-LogEntry ("`$Filter='{0}'" -f $Filter) -Source ${CmdletName} -Severity 4 -Outhost 
                Write-LogEntry ("`$FilterArg='{0}'" -f $FilterArg.ToString()) -Source ${CmdletName} -Severity 4 -Outhost 
            }
           
        }
    }
    End{
        #wmi queries only pulls msi installers details
        If($WMIQuery){
            $InstalledProducts = $Products | Select-Object @{N='Publisher';E={$_.Vendor}},`
                @{N='Name';E={$_.Name}},`
                @{N='Version';E={$_.Version}},`
                @{Label='Uninstall';Expression={"msiexec /X$($_.IdentifyingNumber) /quiet /norestart"}},`
                @{Label='GUID';Expression={$_.IdentifyingNumber}}
        }
        Else{
            $InstalledProducts = $Products | Select-Object Publisher,DisplayName,DisplayVersion,`
                @{Label="Uninstall";Expression={($_.UninstallString).replace('/I','/X')}},`
                @{Label="GUID";Expression={$_.PSChildName}}
        }


        Write-LogEntry ("PASSED VARIABLES:") -Source ${CmdletName} -Severity 4 -Outhost 
        Write-LogEntry ("`$InstalledProducts='{0}'" -f $InstalledProducts) -Source ${CmdletName} -Severity 4 -Outhost
        return $InstalledProducts
    }

}


Function Get-MSIProperties {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.IO.FileInfo] $path,

        [string[]] $properties = @('Manufacturer','ProductCode', 'ProductVersion', 'ProductName','ProductLanguage')
    )
    begin {
        $windowsInstaller = (New-Object -ComObject WindowsInstaller.Installer)
        $Path = Get-ChildItem -Path $Path
    }
    process {
        $table = @{}
        $msi = $windowsInstaller.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $windowsInstaller, @($Path.FullName, 0))
    
        foreach ($property in $properties) {
            try {
                $view = $msi.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $msi, ("SELECT Value FROM Property WHERE Property = '$($property)'"))
                $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null)
                $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
                $table.add($property, $record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, 1))
            }
            catch {
                $table.add($property, $null)
            }
        }

        $msi.GetType().InvokeMember('Commit', 'InvokeMethod', $null, $msi, $null)
        $view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null)
        $msi = $null
        $view = $null
    }
    end {
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($windowsInstaller) | Out-Null
        [System.GC]::Collect()
        return $table
    }
}

Function Process-Application{
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("EXE","MSI","MSP","CMD","BAT","VBS","NUPKG","PS1","PSD1")]
        [string]$Type,
        [ValidateSet("Install","Uninstall","Update","Repair")]
        [string]$Action,
        [string]$Name,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.IO.FileInfo]$Path,
        [string]$Arguments,
        [string]$IgnoreExitCodes
        
    )
    begin {
        ## Get the name of this function
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

        ## Format Log date entry
        $DateEntry = Format-DatePrefix

        #change the action based on the scenario
        Switch ($action) {
			'Install' {$msglabel = 'Installing'; $msiAction = '/i';$msuAction = '';$mspAction = '/p'}
			'Uninstall' {$msglabel = 'Uninstalling'; $msiAction = '/x';$msuAction = '/uninstall /kb';$mspAction = ' MSIPATCHREMOVE='}
			'Update' {$msglabel = 'Updating'; $msiAction = '/update';}
			'Repair' {$msglabel = 'Repairing'; $msiAction = '/f';}
        }
        
    }
    process {
        
        
        # build command and arguments based on Installer type
        #eg. $results = Start-Process $cmd -ArgumentList $args -NoNewWindow -Wait -PassThru
        switch($Type){
            "EXE"   {$cmdScriptBlock = [scriptblock]::create("Start-Process `"$Path`" -ArgumentList `"$Arguments`" -NoNewWindow -Wait -PassThru")}
            "MSI"   {$cmdScriptBlock = [scriptblock]::create("Start-Process msiexec -ArgumentList '$msiAction `"$($Path)`" $Arguments' -NoNewWindow -Wait -PassThru") }
            "MSU"   {$cmdScriptBlock = [scriptblock]::create("Start-Process wusa -ArgumentList '$msuAction `"$($Path)`" $Arguments' -NoNewWindow -Wait -PassThru") }
            "MSP"   {$cmdScriptBlock = [scriptblock]::create("Start-Process msiexec -ArgumentList '$mspAction `"$($Path)`" $Arguments' -NoNewWindow -Wait -PassThru")}
            "CMD"   {$cmdScriptBlock = [scriptblock]::create("Start-Process cmd -ArgumentList '/C $Arguments `"$($Path)`"' -NoNewWindow -Wait -PassThru") }
            "BAT"   {$cmdScriptBlock = [scriptblock]::create("Start-Process cmd -ArgumentList '/K `"$($Path)`" `"$Arguments`"' -NoNewWindow -Wait -PassThru") }
            "VBS"   {$cmdScriptBlock = [scriptblock]::create("Start-Process cscript -ArgumentList '//nologo `"$($Path)`" `"$Arguments`"' -NoNewWindow -Wait -PassThru") }
            "NUPKG" {$cmdScriptBlock = [scriptblock]::create("Install-Package `"$($Path)`" -Force") }
            "PS1"   {$cmdScriptBlock = [scriptblock]::create("Start-Process '$PSHOME\powershell.exe' -ArgumentList '-ExecutionPolicy Bypass -STA -NoProfile -NoLogo -Windowstyle Hidden -File `"$($Path)`"' -NoNewWindow -Wait -PassThru") }
            "PSD1"  {$cmdScriptBlock = [scriptblock]::create("Start-Process '$PSHOME\powershell.exe' -ArgumentList '-ExecutionPolicy Bypass -NoExit -Command `"& Import-Module $($Path)`" `"$Arguments`"' -NoNewWindow -Wait -PassThru") }
        }

        Try{
            Write-LogEntry ("{1} {0}..." -f $AppName,$msglabel) -Source ${CmdletName} -Outhost
            Write-LogEntry ("RUNNING COMMAND: {0}" -f $cmdScriptBlock.ToString()) -Source ${CmdletName} -Severity 4 -Outhost
            $time = [System.Diagnostics.Stopwatch]::StartNew()
            $results = Invoke-Command -ScriptBlock $cmdScriptBlock
            $time.Stop()
            $sw = Format-ElapsedTime($time.Elapsed)
        }
        Catch{
            Write-LogEntry ("Failed to install [{0}] with error message: {1}" -f $AppName,$_.Exception.Message) -Source ${CmdletName} -Severity 3 -Outhost  
            Exit -1
        }

        #if installer has an error other than 0, and is set in the IgnoreErroCodes config
        $ignoredCode = $false
        #build an Array of exit codes
        [array]$ignoreArray = $IgnoreExitCodes -split ','
        #loop the array looking for exist code that matches
        foreach($code in $ignoreArray){
            If($results.ExitCode -eq $code){$ignoredCode = $code}
        }

        $friendlyExitCode = Get-FriendlyMsiExecMsg($results.ExitCode)

        #if the ignore code matches, write status, save errorcode
        If ($results.ExitCode -eq 0) {
            If($Global:Verbose){Write-LogEntry ("Finished installing [{0}] with exitcode: {1}. Install took {2}" -f $AppName,$results.ExitCode,$sw) -Source ${CmdletName} -Severity 4 -Outhost}
            Else{Write-LogEntry ("Finished installing [{0}] with exitcode: {1}" -f $AppName,$results.ExitCode) -Source ${CmdletName} -Severity 0 -Outhost}
        }
        ElseIf ($ignoredCode){
            Write-LogEntry ("Finished installing [{0}] with ignored exitcode: {1} {2}" -f $AppName,$results.ExitCode,$friendlyExitCode) -Source ${CmdletName} -Severity 0 -Outhost
        }
        Else{
            Write-LogEntry ("Failed to install [{0}] with exitcode: {1} {2}" -f $AppName,$results.ExitCode,$friendlyExitCode) -Source ${CmdletName} -Severity 3 -Outhost
            Exit $results.ExitCode
        }
    }
}


##*===========================================================================
##* VARIABLES
##*===========================================================================
## Instead fo using $PSScriptRoot variable, use the custom InvocationInfo for ISE runs
If (Test-Path -LiteralPath 'variable:HostInvocation') { $InvocationInfo = $HostInvocation } Else { $InvocationInfo = $MyInvocation }
[string]$scriptDirectory = Split-Path $MyInvocation.MyCommand.Path -Parent
[string]$scriptName = Split-Path $MyInvocation.MyCommand.Path -Leaf
$DateEntry = Format-DatePrefix

#Create Paths and variables
$SourcePath = Join-Path $scriptDirectory -ChildPath Source
$SettingsFile = Join-Path $scriptDirectory -ChildPath $SettingsName

$Global:Verbose = $false
If($PSBoundParameters.ContainsKey('Debug') -or $PSBoundParameters.ContainsKey('Verbose')){
    $Global:Verbose = $PsBoundParameters.Get_Item('Verbose')
    $VerbosePreference = 'Continue'
    Write-Verbose ("[{0}] [{1}] :: VERBOSE IS ENABLED." -f $DateEntry,$scriptName)
}
Else{
    $VerbosePreference = 'SilentlyContinue'
}

#get content of xml file
Try { 
    [xml]$Settings = Get-Content $SettingsFile 
    [string]$Name = $Settings.xml.Details.Name
    [string]$LogName = ($Settings.xml.Details.InstallName) -replace '\s',''
    $Version = $Settings.xml.Details.Version
}
Catch { 
    $ErrorMsg = $_.Exception.Message
    Write-Host ("[{0}] [{1}] :: Failed to get Settings from [{2}] with error: {3}" -f $DateEntry,$scriptName,$SettingsFile,$ErrorMsg) -ForegroundColor Red
    Exit -1
}

#detect if running in SMS Tasksequence
Try
{
	$tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment
	#$logPath = $tsenv.Value("LogPath")
    $LogPath = $tsenv.Value("_SMSTSLogPath")
}
Catch {
	Write-Warning ("[{0}] [{1}] :: TS environment not detected. Assuming stand-alone mode." -f $DateEntry,$scriptName)
	$LogPath = $env:TEMP
}


[string]$FileName = $LogName +'.log'
$Global:LogFilePath = Join-Path -Path $LogPath -ChildPath $FileName

Write-LogEntry ("Using Settings File: [{0}]" -f $SettingsFile) -Severity 4 -Outhost  

#taking from AppdeployToolkitMain.ps1
[boolean]$Is64Bit = [boolean]((Get-WmiObject -Class 'Win32_Processor' | Where-Object { $_.DeviceID -eq 'CPU0' } | Select-Object -ExpandProperty 'AddressWidth') -eq 64)
If ($Is64Bit) { [string]$envOSArchitecture = 'x64' } Else { [string]$envOSArchitecture = 'x86' }

$AppCount = 0
#Actual Install
Write-LogEntry ("Installing [{0}] version [{1}]..." -f $DateEntry,$scriptName,$Name,$Version) -Severity 4 -Outhost 

##*===============================================
##* MAIN
##*===============================================
foreach ($App in $Settings.xml.Application) {
    $AppCount = $AppCount + 1
    [string]$AppName = $App.Name
    [string]$AppInstaller = $App.Installer
    If($InstallerArg){$AppInstaller = $AppInstaller.Replace("[InstallArgument]",$InstallerArg)}
    If(!($AppInstaller) -or ($AppInstaller -eq '[AUTO]') ){
        Write-LogEntry ("No Installer Specified, scanning source path [{0}] for file type [{1}]" -f $SourcePath,$App.InstallerType) -Severity 4 -Outhost 
        $AppInstaller = (Get-ChildItem -Path $SourcePath -Filter *.$($App.InstallerType) -Recurse | Select -First 1).FullName
    }
    [string]$AppInstallerType = $App.InstallerType

    [string]$AppInstallSwitches = $App.InstallSwitches
    If($SwitchArg){$AppInstallSwitches = $AppInstallSwitches.Replace("[SwitchArgument]",$SwitchArg)}
   
    #Process Dynamic Values if found
    switch -regex ($AppInstallSwitches){
        "\[SourcePath\]"  {$AppInstallSwitches = $AppInstallSwitches.replace("[SourcePath]",$SourcePath)}
        "\[RootPath\]"    {$AppInstallSwitches = $AppInstallSwitches.replace("[RootPath]",$scriptDirectory)}
        "\[TSEnv-(.*?)\]" {If($AppInstallSwitches -match "\[TSEnv-(.*?)\]"){$AppInstallSwitches = $AppInstallSwitches.replace($matches[1],$tsenv.Value($matches[1]))}}
    }

    [string]$AppSupportedArc = $App.SupportedArc
    [string]$AppDetectionType = $App.DetectionType.ToUpper()
    [string]$AppDetectionRule = $App.DetectionRule
    [boolean]$ValidateInstall = [boolean]::Parse($App.ValidateInstall)
    If($DetectionArg){$AppDetectionRule = $AppDetectionRule.Replace("[DetectArgument]",$DetectionArg)}
    Write-LogEntry ("Processing Application {0}" -f $AppCount) -Severity 1 -Outhost
    Write-LogEntry ("==========================") -Severity 1 -Outhost
    Write-LogEntry ("VARIABLE OUTPUT:") -Severity 4 -Outhost
    Write-LogEntry ("-----------------------------------------") -Severity 4 -Outhost
    Write-LogEntry ("`$AppName='{0}'" -f $AppName) -Severity 4 -Outhost
    Write-LogEntry ("`$AppInstaller='{0}'" -f $AppInstaller) -Severity 4 -Outhost
    Write-LogEntry ("`$AppInstallSwitches='{0}'" -f $AppInstallSwitches) -Severity 4 -Outhost
    Write-LogEntry ("`$AppInstallerType='{0}'" -f $AppInstallerType) -Severity 4 -Outhost
    Write-LogEntry ("`$AppSupportedArc='{0}'" -f $AppSupportedArc) -Severity 4 -Outhost
    Write-LogEntry ("`$AppDetectionType='{0}'" -f $AppDetectionType) -Severity 4 -Outhost   

    #if installtype is set to uninstall/remove, configure action
    If( ($AppInstallerType -eq "Uninstall") -or ($AppInstallerType -eq "Remove")  ){
        $AppInstallerAction = "Uninstall"
        $AppInstallerType = $null

        #build installer path (just name)
        $AppInstallerPath = $AppInstaller
    }
    Else{
        $AppInstallerAction = "Install"

        #determine is path is absolute
        #if not absolute, see if path exists from relative
        If([System.IO.Path]::IsPathRooted($AppInstaller)){
            $AppInstallerPath = $AppInstaller
        }
        Else{
            #build installer path (from source folder)
            $AppInstallerPath = Join-Path $SourcePath -ChildPath $AppInstaller 
            
        }

        If(Test-Path $AppInstallerPath){
            #get the extension of installername
            [string]$dotExtension = [System.IO.Path]::GetExtension($AppInstallerPath) 
        
            #if no installer type is specified, try to get the extension from path
            If(!$AppInstallerType){ 
                #get the extension of installername
                [string]$dotExtension = [System.IO.Path]::GetExtension($AppInstallerPath)
                $AppInstallerType = $dotExtension.replace('.','').ToUpper()  
            }
            Else{
                # format extension type (capitalize and remove dot)
                $AppInstallerType = $AppInstallerType.replace('.','').ToUpper() 
            }
        }
        Else{
            Write-LogEntry ("Path [{0}] was not found! Unable to process application..." -f $AppInstallerPath) -Severity 2 -Outhost
            continue  # <- skip just this iteration, but continue loop
        }
    }

    Write-LogEntry ("`$AppInstallerAction='{0}'" -f $AppInstallerAction) -Severity 4 -Outhost
    Write-LogEntry ("`$AppInstallerPath='{0}'" -f $AppInstallerPath) -Severity 4 -Outhost
    Write-LogEntry ("`$AppInstallerType='{0}'" -f $AppInstallerType) -Severity 4 -Outhost

    If($AppDetectionRule){
        switch($AppDetectionType){
            #Build Detection Rules for REG, then split rule to grab registry Keypath, KeyName, and KeyValue
            #eg. HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Signature Updates,AVSignatureVersion,[Version]
            'REG' {
                    #Split the rules into parts
                    $AppDetectionRuleArray = $AppDetectionRule.Split(",")
                    If ($AppDetectionRuleArray[2]){ 
                        [string]$AppDetectionPath = $AppDetectionRuleArray[0]
                        [string]$AppDetectionName = $AppDetectionRuleArray[1]
                        $AppDetectionValue = $AppDetectionRuleArray[2]
                    } 
                    Else{
                        [string]$AppDetectionPath = $AppDetectionRuleArray[0]
                        [string]$AppDetectionName = $AppDetectionRuleArray[1]
                        $AppDetectionValue = $AppInstaller
                    }
            }

            #Build Detection Rules for FILE, then split rule to grab Path, Name, and value
            #eg. C:\Program Files (x86)\Java\jre1.8.0_181\bin,java.exe,[Version]
            'FILE' {
                    #Split the rules into parts
                    $AppDetectionRuleArray = $AppDetectionRule.Split(",")

                    #if rule is empty or just [AUTO], use installer property for details
                    If(!$AppDetectionRule -or ($AppDetectionRule -match '\[AUTO\]') ){
                        [string]$AppDetectionPath = Split-Path $AppInstallerPath -Parent
                        [string]$AppDetectionName = Split-Path $AppInstallerPath -Leaf
                    }
                    Else{
                        #build first two items from rule
                        [string]$AppDetectionPath = $AppDetectionRuleArray[0]
                        [string]$AppDetectionName = $AppDetectionRuleArray[1]
                    }

                    #check if rule has a third item
                    If ($AppDetectionRuleArray[2]){ 
                        $AppDetectionValue = $AppDetectionRuleArray[2]
                    } 
                    Else{
                        $AppDetectionValue = $AppInstaller
                    }
            }

            #Build Detection Rules for GUID, then split to grab guid and value
            #eg. {3dec9467-d9ad-42df-8e84-888057bac8f1},[Version]
            'GUID' {
                    #Split the rules into parts
                    $AppDetectionRuleArray = $AppDetectionRule.Split(",")

                    #if rule is empty or just [AUTO], read msi tables for details
                    If(!$AppDetectionRule -or ($AppDetectionRule -match '\[AUTO\]') -and [System.IO.Path]::GetExtension($AppInstallerPath) -eq '.msi' ){
                        #default rule for GUID
                        $AppDetectionRule = "$AppInstallerPath,[Name]"
                        Write-LogEntry ("[CMDLET] Get-MSIProperties -Path $AppInstallerPath") -Severity 4 -Outhost
                        $MSIProperties = Get-MSIProperties -Path $AppInstallerPath
                        $MSIPropCode = $MSIProperties.ProductCode

                        $AppDetectionPath = "[AUTO]"
                        $AppDetectionName = $AppName
                        $AppDetectionValue = $MSIPropCode
                    }

                    #if rule has a guid in it but its not an MSI (eg. exe bootstrapper)
                    ElseIf($AppDetectionRule -match '{[-0-9A-F]+?}'){
                        $AppDetectionPath = "[AUTO]"
                        $AppDetectionName = $AppName
                        $AppDetectionValue = $Matches[0]
                    }

                    Else{
                        [string]$AppDetectionPath = $AppDetectionRuleArray[0]
                        If ($AppDetectionRuleArray[1]){
                            [string]$AppDetectionName = $AppDetectionRuleArray[0]
                            $AppDetectionValue = $AppDetectionRuleArray[1]
                        }

                        If ($AppDetectionRuleArray[2]){
                            [string]$AppDetectionName = $AppDetectionRuleArray[1]
                            $AppDetectionValue = $AppDetectionRuleArray[2]
                        }
                    }
            }
        }

        #Process Dynamic Values if found
        switch -regex ($AppDetectionValue){
            "\[ValueArg\]"           {If($ValueArg){$AppDetectionValue = $ValueArg}}
            "\[Name\]"               {$AppDetectionValue = $AppName}
            "\[Version\]"            {$AppDetectionValue = $Version}
            "\[Version-(\d)\]"       {If($AppDetectionValue -match "\d"){$AppDetectionValue = $Version.Substring(0,$Version.Length-$matches[0])}}
            "\[(\d)\-Version\]"      {If($AppDetectionValue -match "\d"){$AppDetectionValue = $Version.substring($matches[0])}}
            "\[(\d)\-Version-(\d)\]" {If($AppDetectionValue -match "(\d)-Version-(\d)"){$LastDigit = $Version.Substring(0,$Version.Length-$matches[1]);$AppDetectionValue = $LastDigit.substring($matches[2])}} 
        }
    
        Write-LogEntry ("`$AppDetectionPath='{0}'" -f $AppDetectionPath) -Severity 4 -Outhost
        Write-LogEntry ("`$AppDetectionName='{0}'" -f $AppDetectionName) -Severity 4 -Outhost
        Write-LogEntry ("`$AppDetectionValue='{0}'" -f $AppDetectionValue) -Severity 4 -Outhost
        Write-LogEntry ("-----------------------------------------") -Severity 4 -Outhost

        #scan the system for the application
        Write-LogEntry ("[CMDLET] Scan-ExistingApplication -ScanMethod $AppDetectionType -AppPath '$AppDetectionPath' -AppName '$AppDetectionName' -AppValue '$AppDetectionValue' -AppArc $AppSupportedArc") -Severity 4 -Outhost
        $AppExists = Scan-ExistingApplication -ScanMethod $AppDetectionType -AppPath "$AppDetectionPath" -AppName "$AppDetectionName" -AppValue "$AppDetectionValue" -AppArc $AppSupportedArc -Verbose:$Global:Verbose
        #$AppExists = Scan-ExistingApplication -ScanMethod GUID -AppPath '[AUTO]' -AppName '[GUID]' -AppValue '{C8EA30FC-B20B-465E-9D8A-CDDC09EA72D4}' -AppArc x86
        Write-LogEntry ("`$AppExists='{0}'" -f $AppExists) -Severity 4 -Outhost
    }
    Else{
        #Since now Detection Rule was specified always assume its not installed
        Write-LogEntry ("Detection Rule not specified, Assuming application is not installed..." ) -Severity 4 -Outhost
        $AppExists = $False
    }

    ##*===============================================
	##* UNINSTALLATION SECTION
	##*===============================================
    If($AppInstallerAction -eq 'Uninstall'){
        
        If(!$AppExists){
            Write-LogEntry ("Current application [{0}] is not detected using detection method [{1}]" -f $AppName,$AppDetectionType) -Outhost
            continue  # <- skip just this iteration, but continue loop
        }
        Else{
           switch($AppDetectionType){
                #look for 3 properties from array
                "REG" {                                 
                        If( ($AppSupportedArc -eq 'x86') -and $Is64Bit -and ($AppDetectionRulePath -notmatch 'WOW6432Node')){[string]$regArchSoftPath = '\SOFTWARE\WOW6432Node\'} Else { [string]$regArchSoftPath = '\SOFTWARE\' }
                            
                        $RegProperty = Get-RegistryRoot $AppDetectionRulePath
                        If(Get-ItemProperty ($RegProperty + "\" + $AppDetectionRulePath.Replace('\SOFTWARE\',$regArchSoftPath)) | Select -ExpandProperty $AppDetectionRuleName -ErrorAction SilentlyContinue){
                            Write-LogEntry ("Found registry [{0}\{1}] with keyname [{2}] and value of [{3}]" -f $RegProperty,$AppDetectionRulePath,$AppDetectionRuleName,$AppDetectionRuleValue) -Outhost
                            $UninstallPath = $AppExists.Uninstall
                        }
                      }

                #look for 2 properties from array
                "FILE"{ 
                        $UninstallPath = $AppInstallerPath
                        [string]$dotExtension = [System.IO.Path]::GetExtension($UninstallPath)
                        $AppInstallerType = $dotExtension.replace('.','').ToUpper() 
                        Write-LogEntry ("Application [{0}] is installed in path: {1}, attempting to uninstall..." -f $AppName,$AppDetectionPath) -Outhost 
                      }

                #look for 1 properties from array        
                "GUID"{
                        If($AppExists.PSChildName -match ("^(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}$")){
                            Write-LogEntry ("Application [{0}] is installed with product code: {1}, attempting to uninstall..." -f $AppName,$AppExists.PSChildName) -Outhost
                            $UninstallPath = $AppExists.PSChildName
                        }
                        
                      }
            } 
        }

        #Uninstall Application
        $Result = Process-Application -Type $AppInstallerType -Action Uninstall -Name $AppName -Path $UninstallPath -Arguments $AppInstallSwitches -IgnoreExitCodes $IgnoreExitCodes -Verbose:$Global:Verbose

        If ( $ValidateInstall -and $Result){
            #check if ether ExistingValue is true or has a value
            Write-LogEntry ("[CMDLET] Scan-ExistingApplication -ScanMethod $AppDetectionType -AppPath '$AppDetectionPath' -AppName '$AppDetectionName' -AppValue '$AppDetectionValue' -AppArc $AppSupportedArc") -Severity 4 -Outhost
            $AppExists = Scan-ExistingApplication -ScanMethod $AppDetectionType -AppPath $AppDetectionPath -AppName $AppDetectionName -AppValue $AppDetectionValue  -AppArc $AppSupportedArc -Verbose:$Global:Verbose

            If($AppExists){
                Write-LogEntry ("Application [{0}] is still installed. Uninstall must have failed or theere are registries and files left behind. Detected using detection method [{1}]" -f $AppName,$AppDetectionType) -Severity 3 -Outhost
                $exitcode = -1 
            }
        }

    }

    ##*===============================================
	##* INSTALLATION SECTION
	##*===============================================
    Else{
        $InstalledAlready = $false

        If($AppExists){
            #Compare the value that exists on the system vs the value required by the application
            If($AppExists -gt $AppDetectionValue){
                switch($AppDetectionType){
                    "REG"  {Write-LogEntry ("System's registry value [{0}] is greater than to the application's detection value [{1}]." -f $AppExists,$AppDetectionValue) -Outhost}
                    "FILE" {Write-LogEntry ("Installed File [{0}] is greater than to the application's installer [{1}]." -f $AppExists,$AppDetectionValue) -Outhost}     
                }
                $InstalledAlready = $true
            }
            ElseIf($AppExists -eq $AppDetectionValue){
                If($Global:Verbose){
                    switch($AppDetectionType){
                        "REG"  {Write-LogEntry ("System's registry value [{0}] is equal to the application's detection value [{1}]." -f $AppExists,$AppDetectionValue) -Outhost}
                        "FILE" {Write-LogEntry ("Installed File [{0}] is equal to the application's installer [{1}]." -f $AppExists,$AppDetectionValue) -Outhost}     
                        "GUID" {Write-LogEntry ("Installed application GUID [{0}] is equal to the installer's GUID [{1}]." -f $AppExists,$AppDetectionValue) -Outhost}
                    }
                }
                Else{
                    Write-LogEntry ("Application [{0}] is already installed." -f $AppName) -Outhost
                }
                $InstalledAlready = $true
            }
            Else{
                Write-LogEntry ("Current application [{0}] is installed, but not at version [{1}]" -f $AppName,$AppDetectionValue) -Outhost
            }
        }
        Else{
            Write-LogEntry ("Current application [{0}] is not installed, attempting to install..." -f $AppName) -Outhost
        }

        # Compare architecture to Operating System if x86
        If ( ($AppSupportedArc -eq 'x86' -and $envOSArchitecture -eq 'x86') -or ($AppSupportedArc -eq 'x86' -and $envOSArchitecture -eq 'x64') -or ($AppSupportedArc -eq 'x64' -and $envOSArchitecture -eq 'x64') -or ($AppSupportedArc -eq "Both") ) {
            #Install Application
            If(!$InstalledAlready){$Result = Process-Application -Type $AppInstallerType -Action $AppInstallerAction -Name $AppName -Path $AppInstallerPath -Arguments $AppInstallSwitches -IgnoreExitCodes $IgnoreExitCodes -Verbose:$Global:Verbose}
        }
        Else{
            Write-LogEntry ("Application [{0}] identified architecture is [{1}] which does not match current OS architecture [{2}]. Unable to install." -f $AppName,$AppSupportedArc,$envOSArchitecture) -Severity 2 -Outhost
            $exitcode = 10
            Continue  # <- skip just this iteration, but continue loop
        }
    }

    Write-LogEntry ("Validation after install is set to [{0}]" -f $App.ValidateInstall) -Severity 4 -Outhost

    ##*===============================================
	##* VALIDATION SECTION
	##*===============================================
    #run Validation check if enabled
    If ( $ValidateInstall -and !$InstalledAlready -and $Result){
        #check if ether ExistingValue is true or has a value
        $AppExists = Scan-ExistingApplication -ScanMethod $AppDetectionType -AppPath $AppDetectionPath -AppName $AppDetectionName -AppValue $AppDetectionValue -AppArc $AppSupportedArc -Verbose:$Global:Verbose
 
        If(!$AppExists){
            Write-LogEntry ("Current application [{0}] did not installed correctly or was not detected by detection method [{1}]" -f $AppName,$AppDetectionType) -Severity 3 -Outhost
            $exitcode = 3
        }
        ElseIf($AppExists -ne $AppDetectionValue){
            Write-LogEntry ("Installed application was detected but with version [{0}]. Try reinstalling..." -f $AppExists) -Outhost
            $exitcode = 3
        }
        Else{
            Write-LogEntry ("[{0}] is was detected with version [{1}]" -f $Name,$AppExists) -Outhost
        }
    }

} #end loop

exit $exitcode
