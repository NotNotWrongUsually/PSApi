#Requires -Version 6

Set-Alias -Name 'pcm' -Value 'Publish-Command'
Set-Alias -Name 'upcm' -Value 'Unpublish-Command'
Set-Alias -Name 'gpcm' -Value 'Get-PublishedCommand'

$listener_table = [System.Collections.ArrayList]::new()
$task_list = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))


function Publish-Command {
    <#
    .SYNOPSIS
    Creates a HttpListener, enabling the command to be accessed via HTTP.
    
    .DESCRIPTION
    Long description
    
    .PARAMETER Command
    Specifies the command to make available.
    
    .PARAMETER Hostname
    Specifies the hostname which will serve the requests. Defaults to '+'
    
    .PARAMETER Port
    Specifies the port the HttpListener will listen on.
    
    .PARAMETER Path
    Specifies the path the command will be published on.
    
    .PARAMETER NumberOfThreads
    Specifies the number of runspaces that will be created to handle incoming web-requests. Minimum is 2, since listening for requests and handling requests are done in separate threads.
    
    .PARAMETER LogLocation
    Specifies where the access log for the published command should be created.
    
    .PARAMETER Force
    Indicates that the command should be automatically re-published by unpublishing any existing command with the same name first.
    
    .PARAMETER RunspaceDebugPreference
    Specifies the DebugPreference to be used in the runspaces created. Note that the runspaces are running asynchronously and messages will appear in the console even if you are using it for something else.
    
    .EXAMPLE
    Publish-Command MyFunction

    .EXAMPLE
    # Gets highest CPU consumers in current session
    function Get-HighCpuConsumers {
        param($Number)
        Get-Process | Sort-Object CPU -Descending | Select-Object Name, StartTime, CPU -First $Number | ConvertTo-Json
    }
    
    Publish-Command Get-HighCpuConsumers

    Going to http://myhostname/PSApi/Get-HighCpuConsumers?Number=5 will now show the output of the function, with 5 passed into the Numbers parameter.
    .NOTES
    General notes
    #>
    
    [CmdletBinding(DefaultParameterSetName = 'Publish')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Publish', Position = 0)]
        [Parameter(Mandatory = $true, ParameterSetName = 'AddUrlAcl', Position = 0)]
        [string]
        $Command,
        [Parameter(ParameterSetName = 'Publish')]
        [Parameter(ParameterSetName = 'AddUrlAcl')]
        [string]
        $Hostname = '+',
        [Parameter(ParameterSetName = 'Publish')]
        [Parameter(ParameterSetName = 'AddUrlAcl')]
        [int]
        $Port = 80,
        [Parameter(ParameterSetName = 'Publish')]
        [Parameter(ParameterSetName = 'AddUrlAcl')]
        [string]
        $Path = "PSApi",
        [Parameter(ParameterSetName = 'Publish')]
        [ValidateScript( { if ($_ -lt 2) { Throw "At least 2 threads are required for the server to run properly!" } })][int]$NumberOfThreads = 5,
        [Parameter(ParameterSetName = 'Publish')]
        [string]
        $LogLocation = (Join-Path -Path (get-location).path -ChildPath "$Command`_access.log"),
        [Parameter(ParameterSetName = 'Publish')]
        [switch]
        $Force = $false,
        [Parameter(ParameterSetName = 'Publish')]
        [string]
        $RunspaceDebugPreference = "SilentlyContinue",
        [Parameter(Mandatory = $true, ParameterSetName = 'AddUrlAcl')]
        [switch]
        $AddUrlAcl
    )

    $prefix_string = 'http://' + $Hostname + ':' + $Port + '/' + $Path + '/' + $Command + '/'
    $got_root = IsInSuperuserRole

    if ($AddUrlAcl) {
        New-UrlAclReservation $prefix_string
        break
    }

    if ($Command -in (Get-PublishedCommand).Command) {
        if ($Force) {
            Unpublish-Command -Command $Command
        }
        else {
            Write-Warning "This command is already published!`nIf you wish to re-publish it because you've changed the function, either unpublish it first with Unpublish-Command, or run this command again with the -Force switch set."
            break
        }
    }

    
    # OS specific handling is needed when attempting this command without Root/Administrator.
    if ($got_root) {
        # no worries, we can do everything.
    }
    else {
        if ($IsWindows) {
            if ((netsh http show urlacl $prefix_string) -match [regex]::Escape($prefix_string)) {
                # The prefix_string already has a urlacl. No problems.
            }
            else {
                Write-Warning ("`nPublishing a command on Windows requires Administrator rights!`n`n" + 
                    "There are two ways to fix this:`n`n" +
                    "#1: Running PowerShell as Administrator`n`n" +
                    "#2: If you want to publish a command more permanently, it is advised to add a url reservation.`n" +
                    "To do this run this command again, in an elevated shell, and include the -AddUrlAcl switch.`n" +
                    "After this, you will be able to run the original command from a non-elevated shell.`n")
                break
            }
        }
        elseif ($IsLinux) {
            if ($Port -gt 1023) {
                # No problems, non-root users can do ports above 1023
            }
            else {
                Write-Warning ("Publishing a command on Linux, with a port below 1024 requires superuser rights!`n`n" +
                    "Either re-run this command in a PowerShell running as a superuser, specify a port that is at least 1024," +
                    " or grant an exemption via the OS.")
                break
            }
        }
    } 

    # log_writer is used from inside runspaces, so needs to be thread-safe
    $log_writer = [System.IO.TextWriter]::Synchronized((New-Object System.IO.StreamWriter -ArgumentList $LogLocation, $true))
    $dependencies = @(Resolve-CommandDependencies $Command)

    # This module itself contains the handling functions, so will always be needed
    $dependencies += [PSCustomObject]@{
        Type = "Module"
        Name = (Get-Command "Publish-Command").Source
    }

    $runspacepool = $dependencies | New-CustomRunspacePool -MaximumThreads $NumberOfThreads
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add($prefix_string)
    
    # Add listener to a table in the script scope to aid in making other functions for starting/stopping it, etc.
    [void]$script:listener_table.add([PSCustomObject]@{
            Command      = $Command
            Prefix       = $prefix_string
            Listener     = $listener
            RunspacePool = $runspacepool
            LogFile      = $log_writer
        })
    
    $listener.Start()
    
    # Start the RequestRouter in a separate runspace.
    $params = @{
        listener                = $listener
        RunspacePool            = $runspacepool
        task_list               = $task_list
        log_writer              = $log_writer
        RunspaceDebugPreference = $RunspaceDebugPreference
    }
    $router_runspace = [powershell]::create()
    $router_runspace.RunspacePool = $runspacepool
    [void]$router_runspace.AddCommand("RequestRouter").AddParameters($params)
    $handle = $router_runspace.InvokeAsync()
    [void]$task_list.Add([pscustomobject]@{runspace = $router_runspace; handle = $handle })
}


function RequestRouter ($listener, $runspacepool, $task_list, $log_writer, $RunSpaceDebugPreference) {

    $DebugPreference = $RunSpaceDebugPreference
    Write-Debug "REQUESTROUTER: Starting RequestRouter"

    # The command we want to run is resolved from the listener instead of the incoming url to prevent us from ever
    # running anything except what the user published.
    $command_split = ($listener.Prefixes) -split "/"
    $Command = $command_split[$command_split.length - 2]
    Write-Debug "REQUESTROUTER: Served command is $Command"

    while ($listener.IsListening) {
        $incoming = $listener.GetContextAsync()
        $context = $incoming.Result
        Write-Debug "REQUESTROUTER: Incoming request received. Handing it over to RequestHandler"
            
        # Send this request off for handling in a separate runspace.
        $params = @{
            Context                 = $context
            Command                 = $Command
            log_writer              = $log_writer
            RunSpaceDebugPreference = $RunSpaceDebugPreference
        }

        $handler_runspace = [powershell]::create() 
        $handler_runspace.RunspacePool = $runspacepool
        [void]$handler_runspace.AddCommand("RequestHandler").AddParameters($params)
        $handle = $handler_runspace.InvokeAsync()
        [void]$task_list.Add([pscustomobject]@{runspace = $handler_runspace; handle = $handle; thread = [System.Threading.Thread]::CurrentThread })
        RemoveCompletedTasks
    }
}


function GetTaskList {
    $task_list
}


function RemoveCompletedTasks {
    $completed_tasks = GetTaskList | Where-Object { $_.handle.Status -eq "RanToCompletion" }
    
    foreach ($task in $completed_tasks) {
        $task_list.Remove($task)
    }
}


# The RequestHandler is what does the actual work to evaluate the request and provide the users with a response
function RequestHandler ($context, $Command, $log_writer, $RunSpaceDebugPreference) {
    
    $DebugPreference = $RunSpaceDebugPreference
    Write-Debug "REQUESTHANDLER: starting handling of incoming request"

    $request = $context.Request
    $response = $context.Response
    Write-Debug "REQUESTHANDLER: requested url is $($request.RawUrl)"

    # The querystring is supplied as a NameValueCollection. We'll need to convert this to a hashtable for easy
    # splatting with the call operator.
    $params = @{ }
    $request.QueryString.Keys | ForEach-Object {
        $value = $request.QueryString.GetValues($_)
        # Prevent a one-object array being passed on. Functions which do not take arrays are not happy about this.
        if ($value.count -eq 1) {
            $value = $value[0]
        }
        # This is to handle switch parameters. This feels a bit wrong. Are there actual cases where an empty string
        # would be passed explicitly as a parameter? Assuming no, for now.
        if ($value -eq "" -and $value.count -eq 1) {
            $value = $true
        }
        $params.Add($_, $value)
    }

    # For now error 500 is what will be thrown if the code encounters _any_ error
    try {
        $response_data = & $Command @params -ErrorAction 'stop'
    }
    catch {
        Write-Debug "REQUESTHANDLER: request handling produced an error"
        $response.StatusCode = 500
        $response_data = "<html><head><title>Something bad happened :(</title></head>
                          <body><font face='Courier New'>
                          <h1 style='background-color: #000000; color: #800000'>HTTP 500 - Internal Server Error</h1>
                          <p><b>Command:</b><br>$Command</p>
                          <p><b>Error message:</b><br>$($_.Exception.Message)</p>
                          <p><b>Parameters:</b><br>$((($params | Out-String)  -replace "`n", "<br>") -replace " ", "&nbsp;")</p>                      
                          <p><b>Category info:</b><br>$((($_.CategoryInfo | Out-String) -replace "`n", "<br>") -replace " ", "&nbsp;")</p>
                          </font></body>
                          </html>"
    }
    
    # Next section is special handling to try and do proper return types
    Write-Debug "REQUESTHANDLER: starting inspection of content"
    switch ($response_data.GetType().Name) {
        'String' {
            if (IsJson $resonse_data) {
                $response.ContentType = "application/json;charset=utf-8"
                $response.ContentEncoding = [System.Text.Encoding]::UTF8
            }
            else {
                $response.ContentType = "text/html"
                $response.ContentEncoding = [System.Text.Encoding]::UTF8
            }
        }
        'XmlDocument' {
            $response_data = $response_data.OuterXml
            $response.ContentType = "text/xml;charset=utf-8"
            $response.ContentEncoding = [System.Text.Encoding]::UTF8
        }
        'Bitmap' {
            $response.ContentType = "image/png"
        }
        'BasicHtmlWebResponseObject' {
            $response.ContentType = "text/html;charset=utf-8"
            $response.ContentEncoding = [System.Text.Encoding]::UTF8
            $response_data = $response_data.Content
        }
        Default {
            $response.ContentType = "text/plain;charset=utf-8"
            $response.ContentEncoding = [System.Text.Encoding]::UTF8
            $response_data = $response_data | Out-String 
        }
    }

    Write-Debug "REQUESTHANDLER: writing response"
    # Write a response to the request, distinguishing between images and text
    switch ($response_data.GetType()) {
        'String' {
            [byte[]]$buffer = [System.Text.Encoding]::UTF8.GetBytes($response_data)
        }
        'Bitmap' {
            $memory_stream = New-Object System.IO.MemoryStream
            $response_data.Save($memory_stream, [System.Drawing.Imaging.ImageFormat]::Png)
            [byte[]]$buffer = $memory_stream.GetBuffer()
            $memory_stream.Dispose()
            $response_data.Dispose()
        }
    }

    $response.ContentLength64 = $buffer.length
    $response.OutputStream.Write($buffer, 0, $buffer.length)
    $response.OutputStream.Close()
    Write-Debug "REQUESTHANDLER: response sent"

    # Write a logfile entry in Common Log Format
    $ip = $request.RemoteEndPoint.Address.IPAddressToString
    $log_writer.WriteLine("$ip - - [$(get-date -format o)] `"$($request.HttpMethod) $($request.Url) HTTP/$($request.ProtocolVersion)`" $($response.StatusCode) $($buffer.Length)")
    $log_writer.Flush()
}


# This lucky function owes it's existence solely to the fact that Test-Json is broken
function IsJson ($InputObject) {
    try {
        $InputObject | ConvertFrom-Json -ErrorAction Stop | Out-Null
        $true
    }
    catch {
        $false
    }
}


function Resolve-CommandDependencies {
    [CmdletBinding()]
    param (
        [string[]]$Name
    )

    begin {
        # Used from the InspectCommand function. PSScriptAnalyzer is angry with it, but don't delete it :)
        $seen = New-Object System.Collections.ArrayList
    }

    process {
        $result = foreach ($Command in $Name) {
            InspectCommand $Command
        }
    }

    end {
        $result = $result | Select-Object Type, Name -Unique
        $result
    }
}


function InspectCommand ($name, $from_module = $null) {
    
    $identifier = "$from_module\$name"
    Write-Debug "Check command $identifier"

    # No need to inspect the same command twice
    if ($identifier -in $seen) {
        Write-Debug "$identifier was already checked. Skipping."
        $skip_processing = $true
    }
    

    if (-not $skip_processing) {
        [void]$seen.Add($identifier)

        # '?' specifically screws up by acting some-what like a wildcard, even if wildcards don't work in
        # 'get-command'
        if ($name -eq '?') {
            $check_command = get-alias | Where-Object { $_.Name -eq '?' }
        }
        else {

            try {
                # Try finding the command in the module scope it was mentioned in
                $check_command = (Get-Module $from_module).Invoke( { param([string]$name); get-command $name }, $name)
                Write-Debug "$name retrieved from the module scope for $from_module"
            }
            catch {
                try {
                    # Nope ... then try finding it in the global scope
                    $check_command = Get-Command $name -ErrorAction 'Stop'
                    Write-Debug "$name retrieved from global scope"       
                }
                catch { 
                    # Still nothing, which probably means that this command came from a module within a module like
                    # StorageScripts which is automatically loaded by the Storage module, but is not importable or
                    # visible otherwise. We don't need to load these - the modules should take care of that
                    # themselves.
                    $skip_processing = $true
                }
            }
        }
    }

    if (-not $skip_processing) {
    
        switch ($check_command.CommandType) {
        
            'Cmdlet' {
                # Snapins and modules have to be loaded differently in runspaces. Cmdlets can be either.
                if ($check_command.PSSnapIn) {
                    WriteEntry 'PSSnapIn' $check_command.Source
                }
                else {
                    WriteEntry 'Module' $check_command.Source
                }
                break
            }

            'Function' {
                if ($check_command.CommandType -eq 'Function' -and $check_command.Source) {
                    WriteEntry 'Module' $check_command.Source
                }
                else {
                    WriteEntry 'Function' $check_command.Name
                }
                break
            }

            'Alias' {
                # Aliases need  some special attention. We will both have to include the alias itself, but also any
                # command it references.
                WriteEntry 'Alias' $check_command.Name
                InspectCommand -name $check_command.ReferencedCommand -from_module $check_command.Source
                break
            }

        }

        if ($check_command.ScriptBlock) {
    
            # Tokenize the function for further inspection
            $tokenized = [System.Management.Automation.PSParser]::Tokenize($check_command.Scriptblock, [ref]$null)
    
            # Some variables could be needed. A variable is considered a dependency if it is found within a
            # function and has a non-null value in the current session.
            $variables_to_transfer = $tokenized | Where-Object type -eq 'Variable' | Select-Object -ExpandProperty Content -unique
    
            # This list is straight from about_Automatic_Variables. We don't want to transfer these.
            $variable_blacklist = 'true', 'false', 'null', '_', '$', '?', '^', 'AllNodes', 'Args',
            'ConsoleFileName', 'Error', 'Event', 'EventArgs', 'EventSubscriber', 'ExecutionContext', 'ForEach',
            'Home', 'Host', 'Input', 'LastExitCode', 'Matches', 'MyInvocation', 'NestedPromptLevel', 'OFS', 'PID',
            'Profile', 'PSBoundParameters', 'PsCmdlet', 'PSCommandPath', 'PsCulture', 'PSScriptRoot',
            'PSSenderInfo', 'PsUICulture', 'PsVersionTable', 'Pwd', 'Sender', 'ReportErrorShowExceptionClass',
            'ReportErrorShowInnerException', 'ReportErrorShowSource', 'ReportErrorShowStackTrace', 'ShellID',
            'StackTrace', 'This'
    
            foreach ($var_name in $variables_to_transfer) {
                if ((Get-Variable $var_name -ErrorAction 'SilentlyContinue') -and $var_name -notin $variable_blacklist -and -not $check_command.Source) {
                    WriteEntry 'Variable' $var_name
                }
            }
    
            # The commands used from within this function will have to be inspected as well!
            $Commands_to_inspect = $tokenized | Where-Object type -eq "Command" | Select-Object -ExpandProperty Content -unique
            foreach ($Command_name in $Commands_to_inspect) {
                InspectCommand -name $Command_name -from_module $check_command.Source
            }
        }
    }
}


# Used by Resolve-CommandDependencies to do output. Nothing to see here.
function WriteEntry ($type, $output_name) {
    [PSCustomObject]@{
        Type = $type
        Name = $output_name
    }
}

# Returns a custom runspace pool based on output from Resolve-CommandDependencies. The idea is to generate a
# runspace:
# - with all the necessary stuff in it to serve the function.
# - With no more than the necessary stuff for the sake of security
# - Without requiring the user to explicitly pass in functions, modules, etc.
function New-CustomRunspacePool {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject[]]$required_entities,
        [int]$MaximumThreads = 5
    )

    begin {
        Write-Debug 'Starting custom runspace pool creation'

        # This loads in the powershell Microsoft.PowerShell.Core only. Ideally this would only happen if it was in
        # required_entities, but it is needed since it seems impossible to load it in later (ImportPSSnapIn says it
        # isn't installed!)
        $session_state = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()

    }

    process {
        $required_entities | Where-Object Type -eq 'Module' | ForEach-Object {
            if ($_.Name -notin $session_state.Module.Name) {
                Write-Debug "Adding module: $($_.Name)"
                $module_path = Get-Module $_.Name | Select-Object -ExpandProperty Path
                $session_state.ImportPSModule($module_path)
            }
        }

        $required_entities | Where-Object Type -eq 'PSSnapIn' | ForEach-Object {
            if ($_.Name -notin $session_state.commands.PSSnapIn.Name) {
                Write-Debug "Adding PSSnapIn: $($_.Name)"
                $session_state.ImportPSSnapIn($_.Name, [ref]$null)
            }
        }

        $required_entities | Where-Object Type -eq 'Function' | ForEach-Object {
            if ($_.Name -notin $session_state.commands.Name) {
                Write-Debug "Adding Function: $($_.Name)"
                $Command = Get-Command $_.Name
                $session_state.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Command.Name, $Command.ScriptBlock))
            }
        }

        $required_entities | Where-Object Type -eq 'Variable' | ForEach-Object {
            if ($_.Name -notin $session_state.Variables.Name) {
                Write-Debug "Adding Variable: $($_.Name)"
                $variable = Get-Variable $_.Name
                $session_state.Variables.Add((New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $variable.Name, $variable.Value, $null))
            }
        }

        $required_entities | Where-Object Type -eq 'Alias' | ForEach-Object {
            if ($_.Name -notin $session_state.commands.Name) {
                Write-Debug "Adding Alias: $($_.Name)"
                $alias = Get-Alias $_.Name
                $session_state.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateAliasEntry -ArgumentList $Alias.Name, $Alias.ReferencedCommand))
            }
        }
      
    }
    end {
        $runspace_pool = [runspacefactory]::CreateRunspacePool(1, $MaximumThreads, $session_state, $Host)
        $runspace_pool.Open()
        $runspace_pool
    }
}


function Get-PublishedCommand {
    [CmdletBinding()]
    param (
        [string]$Command = '*'
    )

    $listener_table | Where-Object { $_.command -like $Command }
}

function Unpublish-Command {
    [CmdletBinding()]
    param (
        [string]$Command = '*'
    )
    
    $Commands = Get-PublishedCommand -Command $Command

    foreach ($c in $Commands) {
        $c.Listener.Close()
        $c.RunspacePool.Close()
        $c.LogFile.Close()
        $listener_table.Remove($c)
    }
}


function New-UrlAclReservation ($prefix_string) {
    if ($IsWindows) {
        netsh http add urlacl url=$prefix_string user=$($env:USERDOMAIN)\$($env:USERNAME)

        # Store the urlacl's created by this module so we can help clean them up later if need be
        $storage_path = join-path (split-path (Get-Command publish-command).Module.Path) -ChildPath "Persist" -AdditionalChildPath "urlacls.txt"
        if (-not (Test-Path $storage_path)) {New-Item -Path $storage_path -Force | Out-Null}
        Add-Content -Path $storage_path -Value $prefix_string
    }
    else {
        Write-Warning "The switch AddUrlAcl is only supported on Windows!"
    }
}


function Remove-PSApiUrlAclReservation ($prefix_string) {
    if ($IsWindows) {
        if (IsInSuperuserRole) {
            $storage_path = join-path (split-path (Get-Command Publish-Command).Module.Path) -ChildPath "Persist" -AdditionalChildPath "urlacls.txt"
            netsh http delete urlacl url=$prefix_string
            get-content -Path $storage_path | select-string -pattern [regex]::Escape($prefix_string) -notmatch | Out-File $storage_path
               
        }
        else {
            Write-Warning "You need to be in an elevated shell to do this!"
        }
    }
    else {
        Write-Warning "Only supported on Windows!"
    }
}


# Get prefixes this cmdlet has added
function Get-PSApiUrlAclReservation {
    if ($IsWindows) {
    $storage_path = join-path (split-path (Get-Command publish-command).Module.Path) -ChildPath "Persist" -AdditionalChildPath "urlacls.txt"
    Get-Content -Path $storage_path
    }
    else {
        Write-Warning "Only supported on Windows!"
    }
}


function IsInSuperuserRole {
    if ($IsWindows) {
        $AdminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
        $CurrentRole = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        $CurrentRole.IsInRole($AdminRole)
    }
    elseif ($IsLinux) {
        (id -u) -eq 0
    }
    else {
        $false
    }
}


# Sample functions for testing, delete before publication!
function WriteMeBack ($text) {
    Write-Output $text
}

function Get-MigMan {
    [xml]$char = Get-Content C:\windows\WinSxS\migration.xml
    $char
}

function Get-DiskInfo {
    Get-CimInstance win32_logicaldisk | Select-Object DeviceID, DriveType, ProviderName, VolumeName, Size, FreeSpace | convertto-json
}

function Get-Image {
    $image = New-Object System.Drawing.Bitmap -ArgumentList "D:\backgrounds\ursus1920.jpg"
    $image
}

function Get-HighCpuConsumers {
    param($Number)
    Get-Process | Sort-Object CPU -Descending | Select-Object Name, StartTime, CPU -First $Number | ConvertTo-Json
}
