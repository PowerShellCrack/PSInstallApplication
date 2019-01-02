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

        If($AppArc -eq "Both"){$UseArc = "x86","x64"}Else{$UseArc = $AppArc}
    }
    Process {
        Try{
            $ExistingValue = $null

            switch($ScanMethod){
                #look for 3 properties from array
                "REG" { 
                        $RegProperty = Get-RegistryRoot $AppPath
                        Foreach($arc in $UseArc){
                            #ensure reg path follows architecture structure
                            If( ($arc -eq 'x86') -and $Is64Bit -and ($AppPath -notmatch 'WOW6432Node')){[string]$regArchSoftPath = '\SOFTWARE\WOW6432Node\'} Else { [string]$regArchSoftPath = '\SOFTWARE\' }
                            $RegPath = ($RegProperty + "\" + $AppPath.Replace('\SOFTWARE\',$regArchSoftPath))
                                   
                            #If AUTO is specified for REG type, get installer's uninstall registry key as $AppPath
                            Write-LogEntry ("Scanning registry for [{0}] with [{1}] value equal to or greater than [{2}]" -f $RegPath,$AppName,$AppValue) -Severity 4 -Outhost
                            If($AppPath -eq '[AUTO]'){
                                #(Get-InstalledProduct -Property 'GUID' -Filter '{C8EA30FC-B20B-465E-9D8A-CDDC09EA72D4}' -Arc x86).GUID
                                If(!$ExistingValue){
                                    $ExistingValue = (Get-InstalledProduct -Property $Property -Filter $AppValue -Arc $arc -Verbose:$Global:Verbose).$Property 
                                }  
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
                        Write-LogEntry ("Scanning system for file version [{0}\{1}]" -f $AppPath,$AppName) -Severity 1 -Outhost
                        # check to be sure $AppPath is a filesystem
                        if ($AppPath.provider.name -eq "FileSystem"){
                            $FileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$AppPath\$AppName").FileVersion
                            $ExistingValue = $FileVersion.split(" ")[0].Trim()
                        }
                      }
                #look for 1 properties from array        
                "GUID"{
                        Write-LogEntry ("Scanning system for installed product version: {0}" -f $AppValue) -Severity 1 -Outhost
                        Foreach($arc in $UseArc){
                            #(Get-InstalledProduct -Property 'GUID' -Filter '{C8EA30FC-B20B-465E-9D8A-CDDC09EA72D4}' -Arc x86).GUID
                            Write-LogEntry ("CALL FUNCTION :: Get-InstalledProduct -Property '$Property' -Filter '$AppValue' -Arc $AppArc") -Severity 4 -Outhost
                            If(!$ExistingValue){
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
            "MSI"   {$cmdScriptBlock = [scriptblock]::create("Start-Process msiexec -ArgumentList '$msiAction ""$($Path)"" $Arguments' -NoNewWindow -Wait -PassThru") }
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
            Write-LogEntry ("{0} [{1}]..." -f $msglabel, $Name) -Outhost
            Write-LogEntry ("RUNNING COMMAND: {0}" -f $cmdScriptBlock.ToString()) -Severity 4 -Outhost
            $results = Invoke-Command -ScriptBlock $cmdScriptBlock
        }
        Catch{
            Write-LogEntry ("Failed to install [{0}] with error message: {1}" -f $Name,$_.Exception.Message) -Severity 3 -Outhost  
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
            Write-LogEntry ("Finished installing [{0}] with exitcode: {1}" -f $Name,$results.ExitCode) -Severity 0 -Outhost
        }
        ElseIf ($ignoredCode){
            Write-LogEntry ("Finished installing [{0}] with ignored exitcode: {1}" -f $Name,$results.ExitCode) -Severity 0 -Outhost
        }
        Else{
            Write-LogEntry ("Failed to install [{0}] with exitcode: {1}" -f $Name,$results.ExitCode) -Severity 3 -Outhost
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
    [string]$LogName = $Settings.xml.Details.Name
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
Catch
{
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
foreach ($App in $Settings.xml.Application) {
    $AppCount = $AppCount + 1
    [string]$Name = $App.Name
    [string]$Installer = $App.Installer
    If($InstallerArg){$Installer = $Installer.Replace("[InstallArgument]",$InstallerArg)}
    If(!($Installer) -or ($Installer -eq '[AUTO]') ){
        $Installer = (Get-ChildItem -Path $SourcePath -Filter *.$($App.InstallerType) -Recurse | Select -First 1).FullName
    }
    [string]$InstallerType = $App.InstallerType

    [string]$InstallSwitches = $App.InstallSwitches
    If($SwitchArg){$InstallSwitches = $InstallSwitches.Replace("[SwitchArgument]",$SwitchArg)}
    $InstallSwitches = $InstallSwitches.replace("[SourcePath]",$SourcePath)

    [string]$SupportedArc = $App.SupportedArc
    [string]$DetectionType = $App.DetectionType.ToUpper()
    [string]$DetectionRule = $App.DetectionRule
    If($DetectionArg){$DetectionRule = $DetectionRule.Replace("[DetectArgument]",$DetectionArg)}
    Write-LogEntry ("`r`nProcessing Application {0}" -f $AppCount) -Severity 1 -Outhost
    Write-LogEntry ("==========================") -Severity 1 -Outhost
    Write-LogEntry ("VARIABLE OUTPUT:") -Severity 4 -Outhost
    Write-LogEntry ("-----------------------------------------") -Severity 4 -Outhost
    Write-LogEntry ("`$Name='{0}'" -f $Name) -Severity 4 -Outhost
    Write-LogEntry ("`$Installer='{0}'" -f $Installer) -Severity 4 -Outhost
    Write-LogEntry ("`$InstallSwitches='{0}'" -f $InstallSwitches) -Severity 4 -Outhost
    Write-LogEntry ("`$InstallerType='{0}'" -f $InstallerType) -Severity 4 -Outhost
    Write-LogEntry ("`$SupportedArc='{0}'" -f $SupportedArc) -Severity 4 -Outhost
    Write-LogEntry ("`$DetectionType='{0}'" -f $DetectionType) -Severity 4 -Outhost   

    #if installtype is set to uninstall/remove, configure action
    If( ($InstallerType -eq "Uninstall") -or ($InstallerType -eq "Remove")  ){
        $InstallerAction = "Uninstall"
        $InstallerType = $null

        #build installer path (just name)
        $InstallerPath = $Installer
    }
    Else{
        $InstallerAction = "Install"

        #determine is path is absolute
        #if not absolute, see if path exists from relative
        If([System.IO.Path]::IsPathRooted($Installer)){
            $InstallerPath = $Installer
        }
        Else{
            #build installer path (from source folder)
            $InstallerPath = Join-Path $SourcePath -ChildPath $Installer 
            
        }

        If(Test-Path $InstallerPath){
            #get the extension of installername
            [string]$dotExtension = [System.IO.Path]::GetExtension($InstallerPath) 
        
            #if no installer type is specified, try to get the extension from path
            If(!$InstallerType){ 
                #get the extension of installername
                [string]$dotExtension = [System.IO.Path]::GetExtension($InstallerPath)
                $InstallerType = $dotExtension.replace('.','').ToUpper()  
            }
            Else{
                # format extension type (capitalize and remove dot)
                $InstallerType = $InstallerType.replace('.','').ToUpper() 
            }
        }
        Else{
            Write-LogEntry ("Path [{0}] was not found! Unable to process application..." -f $InstallerPath) -Severity 2 -Outhost
            continue  # <- skip just this iteration, but continue loop
        }
    }

    Write-LogEntry ("`$InstallerAction='{0}'" -f $InstallerAction) -Severity 4 -Outhost
    Write-LogEntry ("`$InstallerPath='{0}'" -f $InstallerPath) -Severity 4 -Outhost
    Write-LogEntry ("`$InstallerType='{0}'" -f $InstallerType) -Severity 4 -Outhost

    switch($DetectionType){
        #Build Detection Rules for REG, then split rule to grab registry Keypath, KeyName, and KeyValue
        #eg. HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Signature Updates,AVSignatureVersion,[Version]
        'REG' {
                #Split the rules into parts
                $DetectionRuleArray = $DetectionRule.Split(",")
                If ($DetectionRuleArray[2]){ 
                    [string]$DetectionPath = $DetectionRuleArray[0]
                    [string]$DetectionName = $DetectionRuleArray[1]
                    $DetectionValue = $DetectionRuleArray[2]
                } 
                Else{
                    [string]$DetectionPath = $DetectionRuleArray[0]
                    [string]$DetectionName = $DetectionRuleArray[1]
                    $DetectionValue = $Installer
                }
        }

        #Build Detection Rules for FILE, then split rule to grab Path, Name, and value
        #eg. C:\Program Files (x86)\Java\jre1.8.0_181\bin,java.exe,[Version]
        'FILE' {
                #Split the rules into parts
                $DetectionRuleArray = $DetectionRule.Split(",")

                #if rule is empty or just [AUTO], use installer property for details
                If(!$DetectionRule -or ($DetectionRule -match '\[AUTO\]') ){
                    [string]$DetectionPath = Split-Path $InstallerPath -Parent
                    [string]$DetectionName = Split-Path $InstallerPath -Leaf
                }
                Else{
                    #build first two items from rule
                    [string]$DetectionPath = $DetectionRuleArray[0]
                    [string]$DetectionName = $DetectionRuleArray[1]
                }

                #check if rule has a third item
                If ($DetectionRuleArray[2]){ 
                    $DetectionValue = $DetectionRuleArray[2]
                } 
                Else{
                    $DetectionValue = $Installer
                }
        }

        #Build Detection Rules for GUID, then split to grab guid and value
        #eg. {3dec9467-d9ad-42df-8e84-888057bac8f1},[Version]
        'GUID' {
                #Split the rules into parts
                $DetectionRuleArray = $DetectionRule.Split(",")

                #if rule is empty or just [AUTO], read msi tables for details
                If(!$DetectionRule -or ($DetectionRule -match '\[AUTO\]') -and [System.IO.Path]::GetExtension($InstallerPath) -eq '.msi' ){
                    #default rule for GUID
                    $DetectionRule = "$InstallerPath,[Name]"
                    Write-LogEntry ("CALL FUNCTION :: Get-MSIProperties -Path $InstallerPath") -Severity 4 -Outhost
                    $MSIProperties = Get-MSIProperties -Path $InstallerPath
                    $MSIPropCode = $MSIProperties.ProductCode

                    $DetectionPath = "[AUTO]"
                    $DetectionName = "[GUID]"
                    $DetectionValue = $MSIPropCode
                }
                #if rule has a guid in it but its not an MSI (eg. exe bootstrapper)
                ElseIf($DetectionRule -match '{[-0-9A-F]+?}'){
                    $DetectionPath = "[AUTO]"
                    $DetectionName = "[GUID]"
                    $DetectionValue = $Matches[0]
                }
                Else{
                    [string]$DetectionPath = $DetectionRuleArray[0]
                    If ($DetectionRuleArray[1]){
                        [string]$DetectionName = $DetectionRuleArray[0]
                        $DetectionValue = $DetectionRuleArray[1]
                    }

                    If ($DetectionRuleArray[2]){
                        [string]$DetectionName = $DetectionRuleArray[1]
                        $DetectionValue = $DetectionRuleArray[2]
                    }
                }
        }
    }

    #Process Dynamic Values if found
    switch -regex ($DetectionValue){
        "\[ValueArg\]"     {If($ValueArg){$DetectionValue = $ValueArg}}
        "\[Name\]"         {$DetectionValue = $Name}
        "\[Version\]"      {$DetectionValue = $Version}
        "\[Version-(\d)\]" {If($DetectionValue -match "\d"){$DetectionValue = $Version.substring($matches[0])}} 
    }

    Write-LogEntry ("`$DetectionPath='{0}'" -f $DetectionPath) -Severity 4 -Outhost
    Write-LogEntry ("`$DetectionName='{0}'" -f $DetectionName) -Severity 4 -Outhost
    Write-LogEntry ("`$DetectionValue='{0}'" -f $DetectionValue) -Severity 4 -Outhost
    Write-LogEntry ("-----------------------------------------") -Severity 4 -Outhost

    #scan the system for the application
    Write-LogEntry ("CALL FUNCTION :: Scan-ExistingApplication -ScanMethod $DetectionType -AppPath '$DetectionPath' -AppName '$DetectionName' -AppValue '$DetectionValue' -AppArc $SupportedArc") -Severity 4 -Outhost
    $AppExists = Scan-ExistingApplication -ScanMethod $DetectionType -AppPath "$DetectionPath" -AppName "$DetectionName" -AppValue "$DetectionValue" -AppArc $SupportedArc -Verbose:$Global:Verbose
    #$AppExists = Scan-ExistingApplication -ScanMethod GUID -AppPath '[AUTO]' -AppName '[GUID]' -AppValue '{C8EA30FC-B20B-465E-9D8A-CDDC09EA72D4}' -AppArc x86
    Write-LogEntry ("`$AppExists='{0}'" -f $AppExists) -Severity 4 -Outhost

    #determine if app is configured to be uninstalled or installed
    If($InstallerAction -eq 'Uninstall'){
        
        If(!$AppExists){
            Write-LogEntry ("Current application [{0}] is not detected using detection method [{1}]" -f $Name,$DetectionType) -Outhost
            continue  # <- skip just this iteration, but continue loop
        }
        Else{
           switch($DetectionType){
                #look for 3 properties from array
                "REG" {                                 
                        If( ($SupportedArc -eq 'x86') -and $Is64Bit -and ($DetectionRulePath -notmatch 'WOW6432Node')){[string]$regArchSoftPath = '\SOFTWARE\WOW6432Node\'} Else { [string]$regArchSoftPath = '\SOFTWARE\' }
                            
                        $RegProperty = Get-RegistryRoot $DetectionRulePath
                        If(Get-ItemProperty ($RegProperty + "\" + $DetectionRulePath.Replace('\SOFTWARE\',$regArchSoftPath)) | Select -ExpandProperty $DetectionRuleName -ErrorAction SilentlyContinue){
                            Write-LogEntry ("Found registry [{0}\{1}] with keyname [{2}] and value of [{3}]" -f $RegProperty,$DetectionRulePath,$DetectionRuleName,$DetectionRuleValue) -Outhost
                            $UninstallPath = $AppExists.Uninstall
                        }
                      }

                #look for 2 properties from array
                "FILE"{ 
                        If(Test-path $AppExists.InstallLocation){
                            $UninstallPath = $AppExists.Uninstall
                            [string]$dotExtension = [System.IO.Path]::GetExtension($UninstallPath)
                            $InstallerType = $dotExtension.replace('.','').ToUpper() 

                            $DetectionPath = Split-Path $UninstallPath -Parent
                            Write-LogEntry ("Application [{0}] is installed in path: {1}, attempting to uninstall..." -f $Name,$DetectionPath) -Outhost
                        } 
                      }

                #look for 1 properties from array        
                "GUID"{
                        If($AppExists.PSChildName -match ("^(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}$")){
                            Write-LogEntry ("Application [{0}] is installed with product code: {1}, attempting to uninstall..." -f $Name,$AppExists.PSChildName) -Outhost
                            $UninstallPath = $AppExists.PSChildName
                        }
                        
                      }
            } 
        }

        #Uninstall Application
        Process-Application -Type $InstallerType -Action Uninstall -Name $Name -Path $UninstallPath -Arguments $InstallSwitches -IgnoreExitCodes $IgnoreExitCodes -Verbose:$Global:Verbose

        If ( [boolean]::Parse($App.DetectionAfter) ){
            #check if ether ExistingValue is true or has a value
            Write-LogEntry ("CALL FUNCTION :: Scan-ExistingApplication -ScanMethod $DetectionType -AppPath '$DetectionPath' -AppName '$DetectionName' -AppValue '$DetectionValue' -AppArc $SupportedArc") -Severity 4 -Outhost
            $AppExists = Scan-ExistingApplication -ScanMethod $DetectionType -AppPath $DetectionPath -AppName $DetectionName -AppValue $DetectionValue  -AppArc $SupportedArc -Verbose:$Global:Verbose

            If($AppExists){
                Write-LogEntry ("Application [{0}] is still installed. Uninstall must have failed or theere are registries and files left behind. Detected using detection method [{1}]" -f $Name,$DetectionType) -Severity 3 -Outhost
                $exitcode = -1 
            }
        }

    }
    Else{

        $InstalledAlready = $false

        If($AppExists){
            If($AppExists -gt $DetectionValue){
                switch($DetectionType){
                    "REG"  {Write-LogEntry ("System's registry value [{0}] is greater than to the application's detection value [{1}]." -f $AppExists,$DetectionValue) -Severity 0 -Outhost}
                    "FILE" {Write-LogEntry ("Installed File [{0}] is greater than to the application's installer [{1}]." -f $AppExists,$DetectionValue) -Severity 0 -Outhost}     
                }
            }
            Else{
                If($Global:Verbose){
                    switch($DetectionType){
                        "REG"  {Write-LogEntry ("System's registry value [{0}] is equal to the application's detection value [{1}]." -f $AppExists,$DetectionValue) -Severity 0 -Outhost}
                        "FILE" {Write-LogEntry ("Installed File [{0}] is equal to the application's installer [{1}]." -f $AppExists,$DetectionValue) -Severity 0 -Outhost}     
                        "GUID" {Write-LogEntry ("Installed application GUID [{0}] is equal to the installer's GUID [{1}]." -f $AppExists,$DetectionValue) -Severity 0 -Outhost}
                    }
                }
                Else{
                    Write-LogEntry ("Application [{0}] is already installed." -f $Name) -Severity 0 -Outhost
                }
            }
            continue
        }
        Else{
            Write-LogEntry ("Current application [{0}] is not installed, attempting to install..." -f $Name) -Outhost
        }

        # Compare architecture to Operating System if x86
        If ( ($SupportedArc -eq 'x86' -and $envOSArchitecture -eq 'x86') -or ($SupportedArc -eq 'x86' -and $envOSArchitecture -eq 'x64') -or ($SupportedArc -eq 'x64' -and $envOSArchitecture -eq 'x64') -or ($SupportedArc -eq "Both") ) {
            #Install Application
            Process-Application -Type $InstallerType -Action $InstallerAction -Name $Name -Path $InstallerPath -Arguments $InstallSwitches -IgnoreExitCodes $IgnoreExitCodes -Verbose:$Global:Verbose
        }
        Else{
            Write-LogEntry ("Application [{0}] identified architecture is [{1}] which does not match current OS architecture [{2}]. Unable to install." -f $Name,$SupportedArc,$envOSArchitecture) -Severity 2 -Outhost
            $exitcode = 10
            Continue  # <- skip just this iteration, but continue loop
        }
    }

    #If true run Detection after
    If ( [boolean]::Parse($App.DetectionAfter) ){
        #check if ether ExistingValue is true or has a value
        $AppExists = Scan-ExistingApplication -ScanMethod $DetectionType -AppPath $DetectionPath -AppName $DetectionName -AppValue $DetectionValue -AppArc $SupportedArc -Verbose:$Global:Verbose
 
        If(!$AppExists){
            Write-LogEntry ("Current application [{0}] did not installed correctly or was not detected by detection method [{1}]" -f $Name,$DetectionType) -Severity 3 -Outhost
            $exitcode = 3
        }
        ElseIf($AppExists -ne $DetectionValue){
            Write-LogEntry ("Installed application was detected but with version [{0}]. Try reinstalling..." -f $AppExists) -Outhost
            $exitcode = 3
        }
        Else{
            Write-LogEntry ("Installed application was detected with version [{0}]." -f $AppExists) -Outhost
        }
    }

} #end loop

exit $exitcode
