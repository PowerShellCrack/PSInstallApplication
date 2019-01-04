Param (
    [Parameter(Mandatory=$false)]
    [string]$SettingsName = "Settings.xml",
    [Parameter(Mandatory=$false)]
    $InstallerArg,
    [Parameter(Mandatory=$false)]
    $SwitchArg,
    [Parameter(Mandatory=$false)]
    $DetectionArg
)

##*===========================================================================
##* FUNCTIONS
##*===========================================================================
function Write-LogEntry {
    param(
        [parameter(Mandatory=$true, HelpMessage="Value added to the log file.")]
        [ValidateNotNullOrEmpty()]
        [string]$Value,

        [parameter(Mandatory=$false)]
        [ValidateSet(0,1,2,3,4)]
        [int16]$Severity,

        [parameter(Mandatory=$false, HelpMessage="Name of the log file that the entry will written to.")]
        [ValidateNotNullOrEmpty()]
        [string]$OutputLogFile = $Global:LogFilePath,

        [parameter(Mandatory=$false)]
        [switch]$Outhost
    )
    
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
    $LogFormat = "<![LOG[$Value]LOG]!>" + "<time=`"$LogTimePlusBias`" " + "date=`"$LogDate`" " + "component=`"$ScriptSource`" " + "context=`"$([Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + "type=`"$Severity`" " + "thread=`"$PID`" " + "file=`"$ScriptSource`">"
    
    # Add value to log file
    try {
        Out-File -InputObject $LogFormat -Append -NoClobber -Encoding Default -FilePath $OutputLogFile -ErrorAction Stop
    }
    catch {
        Write-Host ("Unable to append log entry to [{0}], error: {1}" -f $OutputLogFile,$_.Exception.ErrorMessage) -ForegroundColor Red
    }
    If($Outhost){
        Switch($Severity){
            0       {Write-Host $Value -ForegroundColor Green}
            1       {Write-Host $Value -ForegroundColor Gray}
            2       {Write-Warning $Value}
            3       {Write-Host $Value -ForegroundColor Red}
            4       {If($Global:Verbose){Write-Verbose $Value}}
            default {Write-Host $Value}
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
        $ExistingValue = $false

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
                            Write-LogEntry ("Scanning registry for [{0}] with [{1}] value equal to or greater than [{2}]" -f $RegPath,$AppName,$AppValue) -Severity 4 -Outhost
                            If(!$ExistingValue){
                                If($AppPath -eq '[AUTO]'){
                                #(Get-InstalledProduct -Property 'GUID' -Filter '{C8EA30FC-B20B-465E-9D8A-CDDC09EA72D4}' -Arc x86).GUID
                                Write-LogEntry ("CALL FUNCTION :: Get-InstalledProduct -Property '$Property' -Filter '$AppValue' -Arc $arc") -Severity 4 -Outhost
                                $ExistingValue = (Get-InstalledProduct -Property $Property -Filter $AppValue -Arc $arc -Verbose:$Global:Verbose).$Property 
                                  
                                }
                                Else{
                                    If(Test-Path $RegPath){
                                        Write-LogEntry ("CALL FUNCTION :: Get-ItemProperty -Path '" + $RegPath + "' -Name " + $AppName) -Severity 4 -Outhost
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
                            Write-LogEntry ("Scanning system for file path [{0}]" -f $AppFullPath) -Severity 1 -Outhost
                            
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
                            Write-LogEntry ("Scanning system for installed product [{0} ({1})] with code: {2}" -f $AppName,$arc,$AppValue) -Severity 1 -Outhost
                            If(!$ExistingValue){
                                Write-LogEntry ("CALL FUNCTION :: Get-InstalledProduct -Property '$Property' -Filter '$AppValue' -Arc $arc") -Severity 4 -Outhost
                                #eg. (Get-InstalledProduct -Property 'GUID' -Filter '{C8EA30FC-B20B-465E-9D8A-CDDC09EA72D4}' -Arc x86).GUID
                                $ExistingValue = (Get-InstalledProduct -Property $Property -Filter $AppValue -Arc $arc -Verbose:$Global:Verbose).$Property 
                            }
                          }

                }
            }

        }
        Catch{
            Write-LogEntry ("Failed to scan for existing application [{1}] using [{0}] method. Error: {2} " -f $ScanMethod,$AppName,$ExistingValue.Exception.ErrorMessage) -Severity 3 -Outhost
            If($Global:Verbose){
                Write-LogEntry ("{0} :: PASSED VARIABLES:" -f $MyInvocation.MyCommand.ToString().ToUpper()) -Severity 4 -Outhost 
                Write-LogEntry ("`$AppName='{0}'" -f $AppName) -Severity 4 -Outhost 
                Write-LogEntry ("`$AppPath='{0}'" -f $AppPath) -Severity 4 -Outhost 
                Write-LogEntry ("`$ScanMethod='{0}'" -f $ScanMethod) -Severity 4 -Outhost 
                Write-LogEntry ("`$AppValue='{0}'" -f $AppValue) -Severity 4 -Outhost
            }
            $ExistingValue = $false
        }
    }
    End {
        Write-LogEntry ("{0} :: PASSED VARIABLES:" -f $MyInvocation.MyCommand.ToString().ToUpper()) -Severity 4 -Outhost 
        Write-LogEntry ("`$ExistingValue='{0}'" -f $ExistingValue) -Severity 4 -Outhost
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
        If($Filter){
            #based on property specified, build filter argument scriptblock
            switch($Property){
               "Version" { If($WMIQuery){$FilterArg = "Version = '$Filter'"}Else{$FilterArg = [scriptblock]::create("`$_.DisplayVersion -eq '$Filter'")} }            
               "GUID"    { If($WMIQuery){$FilterArg = "IdentifyingNumber = '$Filter'"}Else{$FilterArg = [scriptblock]::create("`$_.PSChildName -eq '$Filter'")} } 
               "Name"    { If($WMIQuery){$FilterArg = "IdentifyingNumber = '$Filter'"}Else{$FilterArg = [scriptblock]::create("`$_.PSChildName -like '$Filter*'")} } 
               "All"     { If($WMIQuery){$FilterArg = $null}Else{$FilterArg = [scriptblock]::create("`$_.PSPath -like '*'")} }
            }
            Write-LogEntry ("FILTER :: Filter Used: [{0}]" -f $FilterArg) -Severity 4 -Outhost 
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
                Write-LogEntry ("WMI COMMAND: Select * From Win32_product WHERE '$FilterArg'") -Severity 4 -Outhost 
                $Products = Get-WmiObject Win32_Product -Filter $FilterArg
            }
            Else{
                If( ($Arc -eq 'x86') -and $Is64Bit){[string]$regArchPath = '\WOW6432Node\'} Else { [string]$regArchPath = '\' }
                Write-LogEntry ("REGISTRY SEARCH: [HKLM:\SOFTWARE{0}Microsoft\Windows\CurrentVersion\Uninstall] where {1}" -f $regArchPath,$FilterArg.ToString().replace('$_.','')) -Severity 4 -Outhost 
                $Products = Get-ChildItem ("HKLM:\SOFTWARE" + $regArchPath + "Microsoft\Windows\CurrentVersion\Uninstall") | ForEach-Object{ Get-ItemProperty $_.PSPath } | Where $FilterArg
            }
        }
        Catch{
            Write-LogEntry ("Failed to get product details using [{0}] type. Error: {1} " -f $Property,$Products.Exception.ErrorMessage) -Severity 3 -Outhost
            If($Global:Verbose){
                Write-LogEntry ("{0} :: PASSED VARIABLES:" -f $MyInvocation.MyCommand.ToString().ToUpper()) -Severity 4 -Outhost 
                Write-LogEntry ("Failed to get product details, variables passed:") -Severity 4 -Outhost
                Write-LogEntry ("`$Property='{0}'" -f $Property) -Severity 4 -Outhost 
                Write-LogEntry ("`$Filter='{0}'" -f $Filter) -Severity 4 -Outhost 
                Write-LogEntry ("`$FilterArg='{0}'" -f $FilterArg.ToString()) -Severity 4 -Outhost 
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


        Write-LogEntry ("{0} :: PASSED VARIABLES:" -f $MyInvocation.MyCommand.ToString().ToUpper()) -Severity 4 -Outhost 
        Write-LogEntry ("`$InstalledProducts='{0}'" -f $InstalledProducts) -Severity 4 -Outhost
        return $InstalledProducts
    }

}


function Get-MSIProperties {
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

function Process-Application{
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
            Write-LogEntry ("{0} [{1}]..." -f $msglabel, $AppName) -Outhost
            Write-LogEntry ("RUNNING COMMAND: {0}" -f $cmdScriptBlock.ToString()) -Severity 4 -Outhost
            $results = Invoke-Command -ScriptBlock $cmdScriptBlock
        }
        Catch{
            Write-LogEntry ("Failed to install [{0}] with error message: {1}" -f $AppName,$_.Exception.Message) -Severity 3 -Outhost  
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

        #if the ignore code matches, write status, save errorcode
        If ($results.ExitCode -eq 0) {
            Write-LogEntry ("Finished installing [{0}] with exitcode: {1}" -f $AppName,$results.ExitCode) -Severity 0 -Outhost
        }
        ElseIf ($ignoredCode){
            Write-LogEntry ("Finished installing [{0}] with ignored exitcode: {1}" -f $AppName,$results.ExitCode) -Severity 0 -Outhost
        }
        Else{
            Write-LogEntry ("Failed to install [{0}] with exitcode: {1}" -f $AppName,$results.ExitCode) -Severity 3 -Outhost
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

#Create Paths and variables
$SourcePath = Join-Path $scriptDirectory -ChildPath Source
$SettingsFile = Join-Path $scriptDirectory -ChildPath $SettingsName

$Global:Verbose = $false
If($PSBoundParameters.ContainsKey('Debug') -or $PSBoundParameters.ContainsKey('Verbose')){
    $Global:Verbose = $PsBoundParameters.Get_Item('Verbose')
    $VerbosePreference = 'Continue'
    Write-Verbose ("{0} :: VERBOSE IS ENABLED." -f $scriptName)
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
    Write-Host ("{0} :: Failed to get Settings from [{1}] with error: {2}" -f $scriptName,$SettingsFile,$ErrorMsg) -ForegroundColor Red
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
	Write-Warning ("{0} :: TS environment not detected. Assuming stand-alone mode." -f $scriptName)
	$LogPath = $env:TEMP
}


[string]$FileName = $LogName +'.log'
$Global:LogFilePath = Join-Path -Path $LogPath -ChildPath $FileName

Write-LogEntry ("{0} :: Using Settings File: [{1}]" -f $scriptName,$SettingsFile) -Severity 4 -Outhost

#taking from AppdeployToolkitMain.ps1
[boolean]$Is64Bit = [boolean]((Get-WmiObject -Class 'Win32_Processor' | Where-Object { $_.DeviceID -eq 'CPU0' } | Select-Object -ExpandProperty 'AddressWidth') -eq 64)
If ($Is64Bit) { [string]$envOSArchitecture = 'x64' } Else { [string]$envOSArchitecture = 'x86' }

$AppCount = 0
#Actual Install
Write-LogEntry ("Installing [{0}] version [{1}]..." -f $Name,$Version) -Severity 4 -Outhost

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
    $AppInstallSwitches = $AppInstallSwitches.replace("[SourcePath]",$SourcePath)

    [string]$AppSupportedArc = $App.SupportedArc
    [string]$AppDetectionType = $App.DetectionType.ToUpper()
    [string]$AppDetectionRule = $App.DetectionRule
    [boolean]$ValidateInstall = [boolean]::Parse($App.ValidateInstall)
    If($DetectionArg){$AppDetectionRule = $AppDetectionRule.Replace("[DetectArgument]",$DetectionArg)}
    Write-LogEntry ("`r`nProcessing Application {0}" -f $AppCount) -Severity 1 -Outhost
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
                    Write-LogEntry ("CALL FUNCTION :: Get-MSIProperties -Path $AppInstallerPath") -Severity 4 -Outhost
                    $MSIProperties = Get-MSIProperties -Path $AppInstallerPath
                    $MSIPropCode = $MSIProperties.ProductCode

                    $AppDetectionPath = "[AUTO]"
                    $AppDetectionName = "[GUID]"
                    $AppDetectionValue = $MSIPropCode
                }
                #if rule has a guid in it but its not an MSI (eg. exe bootstrapper)
                ElseIf($AppDetectionRule -match '{[-0-9A-F]+?}'){
                    $AppDetectionPath = "[AUTO]"
                    $AppDetectionName = "[GUID]"
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
    Write-LogEntry ("CALL FUNCTION :: Scan-ExistingApplication -ScanMethod $AppDetectionType -AppPath '$AppDetectionPath' -AppName '$AppDetectionName' -AppValue '$AppDetectionValue' -AppArc $AppSupportedArc") -Severity 4 -Outhost
    $AppExists = Scan-ExistingApplication -ScanMethod $AppDetectionType -AppPath "$AppDetectionPath" -AppName "$AppDetectionName" -AppValue "$AppDetectionValue" -AppArc $AppSupportedArc -Verbose:$Global:Verbose
    #$AppExists = Scan-ExistingApplication -ScanMethod GUID -AppPath '[AUTO]' -AppName '[GUID]' -AppValue '{C8EA30FC-B20B-465E-9D8A-CDDC09EA72D4}' -AppArc x86
    Write-LogEntry ("`$AppExists='{0}'" -f $AppExists) -Severity 4 -Outhost

    #determine if app is configured to be uninstalled or installed
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
        Process-Application -Type $AppInstallerType -Action Uninstall -Name $AppName -Path $UninstallPath -Arguments $AppInstallSwitches -IgnoreExitCodes $IgnoreExitCodes -Verbose:$Global:Verbose

        If ( $ValidateInstall ){
            #check if ether ExistingValue is true or has a value
            Write-LogEntry ("CALL FUNCTION :: Scan-ExistingApplication -ScanMethod $AppDetectionType -AppPath '$AppDetectionPath' -AppName '$AppDetectionName' -AppValue '$AppDetectionValue' -AppArc $AppSupportedArc") -Severity 4 -Outhost
            $AppExists = Scan-ExistingApplication -ScanMethod $AppDetectionType -AppPath $AppDetectionPath -AppName $AppDetectionName -AppValue $AppDetectionValue  -AppArc $AppSupportedArc -Verbose:$Global:Verbose

            If($AppExists){
                Write-LogEntry ("Application [{0}] is still installed. Uninstall must have failed or theere are registries and files left behind. Detected using detection method [{1}]" -f $AppName,$AppDetectionType) -Severity 3 -Outhost
                $exitcode = -1 
            }
        }

    }
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
                        "REG"  {Write-LogEntry ("System's registry value [{0}] is equal to the application's detection value [{1}]." -f $AppExists,$AppDetectionValue) -Severity 4 -Outhost}
                        "FILE" {Write-LogEntry ("Installed File [{0}] is equal to the application's installer [{1}]." -f $AppExists,$AppDetectionValue) -Severity 4 -Outhost}     
                        "GUID" {Write-LogEntry ("Installed application GUID [{0}] is equal to the installer's GUID [{1}]." -f $AppExists,$AppDetectionValue) -Severity 4 -Outhost}
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
            If(!$InstalledAlready){Process-Application -Type $AppInstallerType -Action $AppInstallerAction -Name $AppName -Path $AppInstallerPath -Arguments $AppInstallSwitches -IgnoreExitCodes $IgnoreExitCodes -Verbose:$Global:Verbose}
        }
        Else{
            Write-LogEntry ("Application [{0}] identified architecture is [{1}] which does not match current OS architecture [{2}]. Unable to install." -f $AppName,$AppSupportedArc,$envOSArchitecture) -Severity 2 -Outhost
            $exitcode = 10
            Continue  # <- skip just this iteration, but continue loop
        }
    }

    Write-LogEntry ("Validation after install is set to [{0}]" -f $App.ValidateInstall) -Severity 4 -Outhost

    #run Validation check if enabled
    If ( $ValidateInstall ){
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
