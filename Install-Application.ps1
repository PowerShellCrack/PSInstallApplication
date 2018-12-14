Param (
    [Parameter(Mandatory=$false)]
    $SettingsName = "Settings.xml"
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
        [string]$fileArgName = $LogFilePath,

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
        Out-File -InputObject $LogFormat -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
    }
    catch [System.Exception] {
        Write-Host -Message "Unable to append log entry to $LogFilePath file"
    }
    If($Outhost){
        Switch($Severity){
            0       {Write-Host $Value -ForegroundColor Gray}
            1       {Write-Host $Value}
            2       {Write-Warning $Value}
            3       {Write-Host $Value -ForegroundColor Red}
            4       {If($VerbosePreference -ne 'SilentlyContinue'){Write-Verbose $Value}}
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


Function Get-ProductDetails{
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
                Write-Host "WMI Queries can take a long time to process and only pulls products installed by MSI. Please be patient..."
                Write-Verbose "Command: Select * From Win32_product WHERE '$FilterArg'"
                $Products = Get-WmiObject Win32_Product -Filter $FilterArg
            }
            Else{
                If( ($Arc -eq 'x86') -and $Is64Bit){[string]$regArchPath = '\WOW6432Node\'} Else { [string]$regArchPath = '\' }
                Write-Verbose ("Search Registry: [HKLM:\SOFTWARE{0}Microsoft\Windows\CurrentVersion\Uninstall] where {1}" -f $regArchPath,$FilterArg.ToString().replace('$_.',''))
                $Products = Get-ChildItem ("HKLM:\SOFTWARE" + $regArchPath + "Microsoft\Windows\CurrentVersion\Uninstall") | ForEach-Object{ Get-ItemProperty $_.PSPath } | Where $FilterArg
            }
        }
        Catch{
           Write-LogEntry ("Failed to get product details, variables passed:") -Severity 3 -Outhost
           Write-LogEntry ("{0} Function :: `$Property='{1}'" -f $MyInvocation.MyCommand,$Property) -Severity 4 -Outhost 
           Write-LogEntry ("{0} Function :: `$Filter='{1}'" -f $MyInvocation.MyCommand,$Filter) -Severity 4 -Outhost 
           Write-LogEntry ("{0} Function :: `$FilterArg='{1}'" -f $MyInvocation.MyCommand,$FilterArg.ToString()) -Severity 4 -Outhost 
        }
    }
    End{
        #wmi queries only pulls msi installers details
        If($Products){
            If($WMIQuery){
                $Products | Select-Object @{N='Publisher';E={$_.Vendor}},`
                    @{N='DisplayName';E={$_.Name}},`
                    @{N='DisplayVersion';E={$_.Version}},`
                    @{Label='UninstallString';Expression={"msiexec /X$($_.IdentifyingNumber) /quiet /norestart"}},`
                    @{Label='ProductCode';Expression={$_.IdentifyingNumber}}
            }
            Else{
                $Products | Select-Object Publisher,DisplayName,DisplayVersion,`
                    @{Label="UninstallString";Expression={($_.UninstallString).replace('/I','/X')}},`
                    @{Label="ProductCode";Expression={$_.PSChildName}}
            }
        }Else{
            $Products = $false
        }
        Write-LogEntry ("{0} Function :: `$Products='{1}'" -f $MyInvocation.MyCommand,$Products) -Severity 4 -Outhost
        return $Products
    }

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
        [string]$AppArc,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$AppValue
    )
    Begin{
        $ExistingValue = $false

        #determine what architecure is running for regedit path
        [boolean]$Is64Bit = [boolean]((Get-WmiObject -Class 'Win32_Processor' | Where-Object { $_.DeviceID -eq 'CPU0' } | Select-Object -ExpandProperty 'AddressWidth') -eq 64)

        #ensure reg path follows architecture structure
        If( ($Arc -eq 'x86') -and $Is64Bit -and ($AppPath -notmatch 'WOW6432Node')){[string]$regArchSoftPath = '\SOFTWARE\WOW6432Node\'} Else { [string]$regArchSoftPath = '\SOFTWARE\' }

        #based on property specified, build filter argument scriptblock
        switch($AppName){
            "[Version]" { $Property = 'Version'}            
            "[Name]"    { $Property = 'Name'}
            "[GUID]"    { $Property = 'GUID'} 
            default     { $Property = 'All'}
        }
    }
    Process {
        Try{
            switch($ScanMethod){
                #look for 3 properties from array
                "REG" {               
                        #If AUTO is specified for REG type, get installer's uninstall registry key as $AppPath
                        If($AppPath -eq '[AUTO]'){
                            Write-LogEntry ("CALL FUNCTION :: Get-ProductDetails -Property $Property -Filter '$AppValue' -Arc $AppArc") -Severity 4 -Outhost
                            $ExistingValue = Get-ProductDetails -Property $Property -Filter "$AppValue" -Arc $AppArc -Verbose:($VerbosePreference -ne 'SilentlyContinue')
                        }
                        Else{
                            $RegProperty = Get-RegistryRoot $AppPath
                            Write-LogEntry ("Scanning registry for [{0}\{1}] with keyname [{2}] and value of [{3}]" -f $RegProperty,$AppPath,$AppName,$AppValue) -Outhost
                            If(Test-Path ($RegProperty + "\" + $AppPath.Replace('\SOFTWARE\',$regArchSoftPath))){
                                $ExistingValue = Get-ItemProperty ($RegProperty + "\" + $AppPath.Replace('\SOFTWARE\',$regArchSoftPath)) | Select -ExpandProperty $AppName -ErrorAction SilentlyContinue
                            }Else{
                                $ExistingValue = $null
                            }
                        }
                      }
                #look for 2 properties from array
                "FILE"{
                        Write-LogEntry ("Scanning system for file version [{0}\{1}]" -f $AppPath,$AppName) -Outhost
                        # check to be sure $AppPath is a filesystem
                        if ($AppPath.provider.name -eq "FileSystem"){
                            $FileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$AppPath\$AppName").FileVersion
                            $ExistingValue = $FileVersion.split(" ")[0].Trim()
                        }
                      }
                #look for 1 properties from array        
                "GUID"{
                        Write-LogEntry ("Scanning system for installed product version: {0}" -f $AppValue) -Outhost
                        $ExistingValue = Get-ProductDetails -Property $Property -Filter $AppValue -Arc $AppArc -Verbose:($VerbosePreference -ne 'SilentlyContinue')
                      }
            }

        }
        Catch{
            Write-LogEntry ("Failed to scan for existing application; variables passed:") -Severity 3 -Outhost
            Write-LogEntry ("{0} Function :: `$AppName='{1}'" -f $MyInvocation.MyCommand,$AppName) -Severity 4 -Outhost 
            Write-LogEntry ("{0} Function :: `$AppPath='{1}'" -f $MyInvocation.MyCommand,$AppPath) -Severity 4 -Outhost 
            Write-LogEntry ("{0} Function :: `$ScanMethod='{1}'" -f $MyInvocation.MyCommand,$ScanMethod) -Severity 4 -Outhost 
            Write-LogEntry ("{0} Function :: `$AppValue='{1}'" -f $MyInvocation.MyCommand,$AppValue) -Severity 4 -Outhost 
            $ExistingValue = $false
        }
    }
    End {
        Write-LogEntry ("{0} Function :: `$ExistingValue='{1}'" -f $MyInvocation.MyCommand,$ExistingValue) -Severity 4 -Outhost
        return $ExistingValue 
    }
}

function Get-MSIProperties {
  param (
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [System.IO.FileInfo] $path,

    [string[]] $properties = @('ProductCode', 'ProductVersion', 'ProductName', 'Manufacturer', 'ProductLanguage')
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
    return $table
  }
  end {
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($windowsInstaller) | Out-Null
    [System.GC]::Collect()
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
            "MSI"   {$cmdScriptBlock = [scriptblock]::create("Start-Process msiexec -ArgumentList '$msiAction ""$($Path)"" `"$Arguments`"' -NoNewWindow -Wait -PassThru") }
            "MSU"   {$cmdScriptBlock = [scriptblock]::create("Start-Process wusa -ArgumentList '$msuAction `"$($Path)`" `"$Arguments`"' -NoNewWindow -Wait -PassThru") }
            "MSP"   {$cmdScriptBlock = [scriptblock]::create("Start-Process msiexec -ArgumentList '$mspAction `"$($Path)`" `"$Arguments`"' -NoNewWindow -Wait -PassThru")}
            "CMD"   {$cmdScriptBlock = [scriptblock]::create("Start-Process cmd -ArgumentList '/k `"$($Path)`" `"$Arguments`"' -NoNewWindow -Wait -PassThru") }
            "BAT"   {$cmdScriptBlock = [scriptblock]::create("Start-Process cmd -ArgumentList '/k `"$($Path)`" `"$Arguments`"' -NoNewWindow -Wait -PassThru") }
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
            Write-LogEntry ("Finished installing [{0}] with exitcode: {1}" -f $Name,$results.ExitCode) -Outhost
        }
        ElseIf ($ignoredCode){
            Write-LogEntry ("Finished installing [{0}] with ignored exitcode: {1}" -f $Name,$results.ExitCode) -Outhost
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
#$VerbosePreference = 'Continue'
#$VerbosePreference = 'SilentlyContinue'

$Verbose = $false
if ($PSBoundParameters.ContainsKey('Verbose')) { 
    # Command line specifies -Verbose[:$false]
    $Verbose = $PsBoundParameters.Get_Item('Verbose')
}

## Instead fo using $PSScriptRoot variable, use the custom InvocationInfo for ISE runs
If (Test-Path -LiteralPath 'variable:HostInvocation') { $InvocationInfo = $HostInvocation } Else { $InvocationInfo = $MyInvocation }
[string]$scriptDirectory = Split-Path $MyInvocation.MyCommand.Path -Parent
[string]$scriptName = Split-Path $MyInvocation.MyCommand.Path -Leaf

#Create Paths and variables
$SourcePath = Join-Path $scriptDirectory -ChildPath Source
$SettingsFile = Join-Path $scriptDirectory -ChildPath $SettingsName

#get content of xml file
Try { 
    [xml]$Settings = Get-Content $SettingsFile 
    [string]$LogName = $Settings.xml.Details.Name
    $Version = $Settings.xml.Details.Version
}
Catch { 
  $ErrorMsg = $_.Exception.Message
  Write-LogEntry "Failed to get Settings from $SettingsFile with error $ErrorMsg"
  $LASTEXITCODE = "-1"
  Break
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
	Write-Warning "TS environment not detected. Assuming stand-alone mode."
	$LogPath = $env:TEMP
}

[string]$FileName = $LogName +'.log'
$LogFilePath = Join-Path -Path $LogPath -ChildPath $FileName

Write-LogEntry ("Found Settings File:: {0}" -f $SettingsFile) -Severity 4 -Outhost

#taking from AppdeployToolkitMain.ps1
[boolean]$Is64Bit = [boolean]((Get-WmiObject -Class 'Win32_Processor' | Where-Object { $_.DeviceID -eq 'CPU0' } | Select-Object -ExpandProperty 'AddressWidth') -eq 64)
If ($Is64Bit) { [string]$envOSArchitecture = 'x64' } Else { [string]$envOSArchitecture = 'x86' }

#Actuall Install
foreach ($App in $Settings.xml.Application) {

    [string]$Name = $App.Name
    [string]$InstallerName = $App.InstallerName
    [string]$InstallerType = $App.InstallerType
    [string]$InstallSwitches = $App.InstallSwitches
    [string]$SupportedArc = $App.SupportedArc
    [string]$DetectionType = $App.DetectionType.ToUpper()
    [string]$DetectionRule = $App.DetectionRule

    Write-LogEntry ("Variables:") -Severity 4 -Outhost
    Write-LogEntry ("`$Name='{0}'" -f $Name) -Severity 4 -Outhost
    Write-LogEntry ("`$InstallerName='{0}'" -f $InstallerName) -Severity 4 -Outhost
    Write-LogEntry ("`$InstallerType='{0}'" -f $InstallerType) -Severity 4 -Outhost
    Write-LogEntry ("`$SupportedArc='{0}'" -f $SupportedArc) -Severity 4 -Outhost
    Write-LogEntry ("`$DetectionType='{0}'" -f $DetectionType) -Severity 4 -Outhost
    
    
    #if installtype is set to unistall or remove
    If( ($InstallerType -eq "Uninstall") -or ($InstallerType -eq "Remove")  ){
        $InstallerAction = "Uninstall"
        $InstallerType = $null

        #build installer path (just name)
        $InstallerPath = $InstallerName
    }
    #if installtype empty, default to install
    ElseIf(!$InstallerType){
        $InstallerAction = "Install"
      
        #build installer path (from source folder)
        $InstallerPath = Join-Path $SourcePath -ChildPath $InstallerName

        #get the extension of installername
        [string]$dotExtension = [System.IO.Path]::GetExtension($InstallerPath)
        $InstallerType = $dotExtension.replace('.','').ToUpper()  
    }
    Else{
        $InstallerAction = "Install"

        #build installer path (from source folder)
        $InstallerPath = Join-Path $SourcePath -ChildPath $InstallerName

        # format extension type (capitalize and remove dot)
        $InstallerType = $InstallerType.replace('.','').ToUpper()
         
    }
    Write-LogEntry ("`$InstallerAction='{0}'" -f $InstallerAction) -Severity 4 -Outhost
    Write-LogEntry ("`$InstallerPath='{0}'" -f $InstallerPath) -Severity 4 -Outhost
    Write-LogEntry ("`$InstallerType='{0}'" -f $InstallerType) -Severity 4 -Outhost


    #if AUTO or empty, build the missing values (comma deliminated)
    #eg. path,name,value
    If(!$DetectionRule -or ($DetectionRule -eq '[AUTO]') ){
        If( ($DetectionType -eq 'GUID') -or ($dotExtension -eq '.msi') ){
            #When AppPath is set to AUTO, scan file for details (MSI Only)
            #App path will have a appended fullinstallerpath, grab it to process
            #$FullPath = $InstallerPath.Split(",")[1]
            If([System.IO.Path]::GetExtension($InstallerPath) -eq '.msi'){
                $MSIProperties = Get-MSIProperties -Path $InstallerPath
                $MSIPropCode = $MSIProperties.ProductCode

                $DetectionRule = "[AUTO],[GUID],$MSIPropCode"
            }
            Else{
                $DetectionRule = "$InstallerPath,[Name]"
            }
        }
        Else{
            #tell script to scan registry for exe uninstallstring (if exists)
            $DetectionRule = "[AUTO],[Name],$InstallerName"
        }
    } 


    #split out the Detection rule array by commas and build individual proeprties
    #should have a total of three values
    Write-LogEntry ("`$DetectionRule='{0}'" -f $DetectionRule) -Severity 4 -Outhost
    
    #split out Detection rule to grab Path, Name, and version
    #eg. C:\Program Files (x86)\Java\jre1.8.0_181\bin,java.exe,[Version]
    $DetectionRuleArray = $DetectionRule.Split(",")

    If($DetectionType -eq 'File'){
        $DetectionPath = Split-Path $DetectionRuleArray[0] -Parent
    }
    Else{
        $DetectionPath = $DetectionRuleArray[0]
    }
    
    Write-LogEntry ("`$DetectionPath='{0}'" -f $DetectionPath) -Severity 4 -Outhost

    #does the set have second array item
    If($DetectionType -eq 'File'){
        [string]$DetectionName = Split-Path $DetectionRuleArray[0] -Leaf
    }
    Else{
        [string]$DetectionName = $DetectionRuleArray[1]
    }
    Write-LogEntry ("`$DetectionName='{0}'" -f $DetectionName) -Severity 4 -Outhost

    #does the set have third array item
    If ($DetectionRuleArray[2]){ 
        $DetectionValue = $DetectionRuleArray[2]
    } 
    Else{
        $DetectionValue = $InstallerName
    }
    Write-LogEntry ("`$DetectionValue='{0}'" -f $DetectionValue) -Severity 4 -Outhost
    
    #scan the system for the application
    Write-LogEntry ("CALL FUNCTION :: Scan-ExistingApplication -ScanMethod $DetectionType -AppPath '$DetectionPath' -AppName '$DetectionName' -AppValue '$DetectionValue' -AppArc $SupportedArc") -Severity 4 -Outhost
    $AppExists = Scan-ExistingApplication -ScanMethod $DetectionType -AppPath "$DetectionPath" -AppName "$DetectionName" -AppValue "$DetectionValue" -AppArc $SupportedArc -Verbose:($VerbosePreference -ne 'SilentlyContinue')
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
                            $UninstallPath = $AppExists.UninstallString
                        }
                      }

                #look for 2 properties from array
                "FILE"{ 
                        If(Test-path $AppExists.InstallLocation){
                            $UninstallPath = $AppExists.UninstallString
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
        Process-Application -Type $InstallerType -Action Uninstall -Name $Name -Path $UninstallPath -Arguments $InstallSwitches -IgnoreExitCodes $IgnoreExitCodes -Verbose:($VerbosePreference -ne 'SilentlyContinue')

        If ( [boolean]::Parse($App.DetectionAfter) ){
            #check if ether ExistingValue is true or has a value
            Write-LogEntry ("CALL FUNCTION :: Scan-ExistingApplication -ScanMethod $DetectionType -AppPath '$DetectionPath' -AppName '$DetectionName' -AppValue '$DetectionValue' -AppArc $SupportedArc") -Severity 4 -Outhost
            $AppExists = Scan-ExistingApplication -ScanMethod $DetectionType -AppPath $DetectionPath -AppName $DetectionName -AppValue $DetectionValue  -AppArc $SupportedArc -Verbose:($VerbosePreference -ne 'SilentlyContinue')

            If($AppExists){
                Write-LogEntry ("Application [{0}] is still installed. Uninstall must have failed or theere are registries and files left behind. Detected using detection method [{1}]" -f $Name,$DetectionType) -Severity 3 -Outhost
                $exitcode = -1 
            }
        }

    }
    Else{

        #test path to ensure its there
        If(!(Test-Path $InstallerPath)){
            Write-LogEntry ("Application file [{0}] was not found!" -f $InstallerPath) -Severity 3 -Outhost
            $exitcode = 2
            continue
        }

        $InstalledAlready = $false

        If($AppExists){
            Write-LogEntry ("Application [{0}] is already installed. Used detection method: [{1}]" -f $Name,$DetectionType) -Outhost 
            continue
        }
        Else{
            Write-LogEntry ("Current application [{0}] is not installed, attempting to install..." -f $Name) -Outhost
        }

        # Compare architecture to Operating System
        If ( ($SupportedArc -eq $envOSArchitecture) -or ($SupportedArc -eq "Both") ) {
            #Install Application
            Process-Application -Type $InstallerType -Action $InstallerAction -Name $Name -Path $InstallerPath -Arguments $InstallSwitches -IgnoreExitCodes $IgnoreExitCodes -Verbose:($VerbosePreference -ne 'SilentlyContinue')
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
        $AppExists = Scan-ExistingApplication -ScanMethod $DetectionType -AppPath $DetectionPath -AppName $DetectionName -AppValue $DetectionValue -AppArc $SupportedArc -Verbose:($VerbosePreference -ne 'SilentlyContinue')
 
        If(!$AppExists){
            Write-LogEntry ("Current application [{0}] did not installed corectly or was not detected by detection method [{1}]" -f $Name,$DetectionType) -Severity 3 -Outhost
            $exitcode = 3
        }
    }
} #end loop

exit $exitcode