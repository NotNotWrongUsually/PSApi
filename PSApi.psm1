#Requires -Version 6

Set-Alias -Name 'pcm' -Value 'Publish-Command'
Set-Alias -Name 'upcm' -Value 'Unpublish-Command'
Set-Alias -Name 'gpcm' -Value 'Get-PublishedCommand'

$listener_table = [System.Collections.ArrayList]::new()
$task_list = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))


function Publish-Command {
    <#
    .SYNOPSIS
    Creates a HttpListener, enabling a command to be accessed via HTTP.
    
    .DESCRIPTION
    Makes a cmdlet or function available over http. Default parameters will use port 80, 5 threads, and the path http://localhost/PSApi/<Command>. Unpublish-Command can be used to undo the publishing of a function. If the served function changes it is necessary to re-publish it. Issuing Publish-Command again with the same parameters and including the -Force switch is useful for this.
    
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
    Specifies where the access log for the published command should be created. Defaults to the location where the command is issued.
    
    .PARAMETER Force
    Indicates that the command should be automatically re-published by unpublishing any existing command with the same name first.
    
    .PARAMETER ShowDebugMessages
    Indicates that debug messages from runspace should be routed to the terminal host.

    .PARAMETER ShowLogMessages
    Indicates that messages that would normally go in the logfile should also be output to the terminal host.

    .PARAMETER AddUrlAcl
    Indicates that instead of publishing the command, a urlacl prefix should be reserved. This will allow the command to be published without administrator rights. Only relevant for Windows.
    
    .PARAMETER JSONErrorMode
    Indicates that 500 error messages should be returned as JSON instead of as HTML.

    .PARAMETER CorsPolicy
    Specifies the CORS policy for the published command. This is only needed if you want a webpage served from another host or port to retrieve results from your published command. Use New-PSApiCorsPolicy to generate a value for this parameter.
    
    .EXAMPLE
    Publish-Command MyFunction

    Publishes MyFunction at http://localhost/PSApi/MyFunction

    .EXAMPLE
    # Gets highest CPU consumers in current session
    function Get-HighCpuConsumers {
        param($Number)
        Get-Process | Sort-Object CPU -Descending | Select-Object Name, StartTime, CPU -First $Number | ConvertTo-Json
    }
    
    Publish-Command Get-HighCpuConsumers

    Going to http://myhostname/PSApi/Get-HighCpuConsumers?Number=5 will now show the output of the function, with 5 passed into the Number parameter.

    .EXAMPLE
    # From an un-elevated Windows shell
    Publish-Command Get-Process
    <results in error message>

    # From an elevated Windows shell
    Publish-Command Get-Process -AddUrlAcl

    # From an un-elevated Windows shell
    Publish-Command Get-Process
    <success!>

    .EXAMPLE
    # I just want CORS to go away
    PS > $cors_policy = New-PSApiCorsPolicy -Allow-Origin '*'
    PS > Publish-Command My-Command -CorsPolicy $cors_policy
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
        [ValidateScript( { if ($_ -gt 2) {$true} else { Throw "At least 2 threads are required for the server to run properly!" } })][int]$NumberOfThreads = 5,
        [Parameter(ParameterSetName = 'Publish')]
        [string]
        $LogLocation = (Join-Path -Path (get-location).path -ChildPath "$Command`_access.log"),
        [Parameter(ParameterSetName = 'Publish')]
        [switch]
        $Force = $false,
        [Parameter(ParameterSetName = 'Publish')]
        [switch]
        $ShowDebugMessages,
        [Parameter(Mandatory = $true, ParameterSetName = 'AddUrlAcl')]
        [switch]
        $AddUrlAcl,
        [Parameter(ParameterSetName = 'Publish')]
        [switch]
        $JSONErrorMode,
        [Parameter(ParameterSetName = 'Publish')]
        [PSCustomObject]
        $CorsPolicy,
        [Parameter(ParameterSetName = 'Publish')]
        [switch]
        $ShowLogMessages
    )

    if (-not (Get-Command $Command -ErrorAction "SilentlyContinue")) {
        Write-Warning "Command $Command not found!"
        break
    }

    if ($Path -ne "") {
        $prefix_string = 'http://' + $Hostname + ':' + $Port + '/' + $Path + '/' + $Command + '/'
    }
    else {
        $prefix_string = 'http://' + $Hostname + ':' + $Port + '/' + $Command + '/'
    }
    
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

    try {
        $listener = New-Object System.Net.HttpListener
        $listener.Prefixes.Add($prefix_string)
        $listener.Start()
    }
    catch {
        Write-Warning "Unable to start listener!"
        throw $_
        break
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

    if ($ShowDebugMessages -or $ShowLogMessages) {
        $host_proxy = $Host
    }
    else {
        $host_proxy = $null
    }

    # We'll need to pass these between runspaces, so putting them in a nice object
    $configurations = [PSCustomObject]@{
        LogWriter     = $log_writer
        JSONErrorMode = $JSONErrorMode
        ShowDebug     = $ShowDebugMessages
        LogToConsole  = $ShowLogMessages
        CorsPolicy    = $CorsPolicy
        HostProxy     = $host_proxy
    }

    # Add information to a table in the script scope to aid in making other functions for starting/stopping it, etc.
    [void]$script:listener_table.add([PSCustomObject]@{
            Command       = $Command
            Prefix        = $prefix_string
            Listener      = $listener
            RunspacePool  = $runspacepool
            Configuration = $configurations
        })
    
    # Start the RequestRouter in a separate runspace.
    $params = @{
        listener      = $listener
        RunspacePool  = $runspacepool
        task_list     = $task_list
        Configuration = $configurations
    }
    $router_runspace = [powershell]::create()
    $router_runspace.RunspacePool = $runspacepool
    [void]$router_runspace.AddCommand("RequestRouter").AddParameters($params)
    $handle = $router_runspace.InvokeAsync()
    [void]$task_list.Add([pscustomobject]@{runspace = $router_runspace; handle = $handle })
}


function RequestRouter ($listener, $runspacepool, $task_list, $configuration) {

    RSDebug "REQUESTROUTER: Starting RequestRouter"

    # The command we want to run is resolved from the listener instead of the incoming url to prevent us from ever
    # running anything except what the user published.
    $command_split = ($listener.Prefixes) -split "/"
    $Command = $command_split[$command_split.length - 2]
    RSDebug "REQUESTROUTER: Served command is $Command"

    while ($listener.IsListening) {
        $finished = $false
        $incoming = $listener.GetContextAsync()

        # A bug causes PowerShell to hang when exiting if a blocking command is running in a runspace.
        # This should ideally be as simple as: $context = $incoming.GetAwaiter().GetResult()
        while (-not $finished) {
            $finished = $incoming.Wait(3000)
        }
        $context = $incoming.Result

        RSDebug "REQUESTROUTER: Incoming request received. Handing it over to RequestHandler"
        # Send this request off for handling in a separate runspace.
        $params = @{
            Context       = $context
            Command       = $Command
            Configuration = $configuration
        }

        $handler_runspace = [powershell]::create() 
        $handler_runspace.RunspacePool = $runspacepool
        [void]$handler_runspace.AddCommand("RequestHandler").AddParameters($params)
        $handle = $handler_runspace.InvokeAsync()
        [void]$task_list.Add([PSCustomObject]@{runspace = $handler_runspace; handle = $handle; thread = [System.Threading.Thread]::CurrentThread })
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
function RequestHandler ($context, $Command, $configuration) {
    
    # $DebugPreference = $RunSpaceDebugPreference   Is this just a leftover?
    RSDebug "REQUESTHANDLER: starting handling of incoming request"

    $request = $context.Request
    $response = $context.Response
    RSDebug "REQUESTHANDLER: requested url is $($request.RawUrl)"

    # Set the specified CORS policy if any and relevant
    if ($null -ne $request.Headers['Origin'] -and $configuration.CorsPolicy) {
        $configuration.CorsPolicy.GetEnumerator() | ForEach-Object {
            $response.Headers.Add($_.Key, $_.Value)
        }

        if ($configuration.CorsPolicy['Access-Control-Allow-Origin'] -ne '*' -and $configuration.CorsPolicy['Access-Control-Allow-Origin'] -ne 'null') {
            if ($request.Headers['Origin'] -in $configuration.CorsPolicy['Access-Control-Allow-Origin'].Replace(' ', '').Split(',')) {
                $response.Headers.Add('Vary', 'Origin')
                $response.Headers.Set('Access-Control-Allow-Origin', $request.Headers['Origin'])
            }
            else {
                $response.Headers.Remove('Access-Control-Allow-Origin')
            }
        }
    }

    $params = @{ }

    if ($request.HttpMethod -eq "GET") {
        # The querystring is supplied as a NameValueCollection. We'll need to convert this to a hashtable for easy
        # splatting with the call operator.
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
    }
    elseif ($request.HttpMethod -eq "POST") {
        $reader = New-Object System.IO.StreamReader -ArgumentList $request.InputStream, $request.ContentEncoding
        $post_data = $reader.ReadToEnd()
        # The parameters can arrive either as a JSON payload, or URL encoded
        if (IsJson $post_data) {
            $params_object = $post_data | ConvertFrom-Json
            $params_object.psobject.properties | ForEach-Object {
                $params.add($_.Name, $_.Value)
            }
        }
        else {
            $parameter_list = $post_data -split '&'
            $parameter_list | ForEach-Object {
                $name, $value = $_ -split '='
                $name = [System.Web.HttpUtility]::UrlDecode($name)
                $value = [System.Web.HttpUtility]::UrlDecode($value)
                if ($value) {
                    $params.Add($name, $value)
                }
            }
        }
        $reader.Dispose()
    }
    elseif ($request.HttpMethod -eq 'OPTIONS') {
        $response.Headers.Add('Allow', 'GET, POST, OPTIONS')
        $response_data = ''
        $skip_processing = $true
    }
    else {
        # Someone is trying to do a request with a method apart from GET, POST or OPTIONS.
        $response.StatusCode = 405
        $response.Headers.Add('Allow', 'GET, POST, OPTIONS')
        $response_data = "HTTP 405 - Method Not Allowed"
        $skip_processing = $true
    }

    # Try to run the users command
    # For now error 500 is what will be thrown if the code encounters _any_ error
    try {
        if (-not $skip_processing) {
            $response_data = & $Command @params -ErrorAction 'stop'
        }
    }
    catch {
        RSDebug "REQUESTHANDLER: request handling produced an error"
        $response.StatusCode = 500
        if ($configuration.JSONErrorMode) {
            $response_data = @{
                message       = $_.Exception.Message
                params        = $params
                category_info = $_.CategoryInfo
                command       = $Command
            } | ConvertTo-JSON
        }
        else {
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
    }
    
    # Next section is special handling to try and do proper return types
    RSDebug "REQUESTHANDLER: starting inspection of content"
    switch ($response_data.GetType().Name) {
        'String' {
            if (IsJson $response_data) {
                RSDebug "REQUESTHANDLER: content determined to be JSON"
                $response.ContentType = "application/json;charset=utf-8"
                $response.ContentEncoding = [System.Text.Encoding]::UTF8
            }
            else {
                RSDebug "REQUESTHANDLER: content determined to be [string], will show as html"
                $response.ContentType = "text/html"
                $response.ContentEncoding = [System.Text.Encoding]::UTF8
            }
        }
        'XmlDocument' {
            RSDebug "REQUESTHANDLER: content determined to be XML"
            $response_data = $response_data.OuterXml
            $response.ContentType = "text/xml;charset=utf-8"
            $response.ContentEncoding = [System.Text.Encoding]::UTF8
        }
        'Bitmap' {
            RSDebug "REQUESTHANDLER: content determined to be an image"
            $response.ContentType = "image/png"
        }
        'BasicHtmlWebResponseObject' {
            RSDebug "REQUESTHANDLER: content determined to be html"
            $response.ContentType = "text/html;charset=utf-8"
            $response.ContentEncoding = [System.Text.Encoding]::UTF8
            $response_data = $response_data.Content
        }
        Default {
            RSDebug "REQUESTHANDLER: could not determine content type. Stringifying and outputting."
            $response.ContentType = "text/plain;charset=utf-8"
            $response.ContentEncoding = [System.Text.Encoding]::UTF8
            $response_data = $response_data | Out-String 
        }
    }

    RSDebug "REQUESTHANDLER: begin writing response"
    # Write a response to the request, distinguishing between images and text
    switch ($response_data.GetType().Name) {
        'String' {
            # If the requestor is ok with getting gzipped data back we'll do that
            if ($null -ne $request.Headers['Accept-Encoding'] -and "gzip" -in $request.Headers.GetValues('Accept-Encoding')) {
                    RSDebug "REQUESTHANDLER: Content is a string and Accept-Encoding contains gzip. Attempt to compress."
                    [byte[]]$content_bytes = [System.Text.Encoding]::UTF8.GetBytes($response_data)
                    $memory_stream = New-Object System.IO.MemoryStream
                    $zip_stream = New-Object System.IO.Compression.GzipStream -ArgumentList $memory_stream, ([System.IO.Compression.CompressionLevel]::Fastest)
                    $zip_stream.Write($content_bytes, 0, $content_bytes.Length)
                    $zip_stream.dispose()
                    $memory_stream.dispose()
                    $response.AddHeader('Content-Encoding', 'gzip')
                    [byte[]]$buffer = $memory_stream.ToArray()
            }
            else {
                [byte[]]$buffer = [System.Text.Encoding]::UTF8.GetBytes($response_data)
            }
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
    RSDebug "REQUESTHANDLER: response sent"

    # Write a logfile entry in Common Log Format
    $ip = $request.RemoteEndPoint.Address.IPAddressToString
    $message = "$ip - - [$(get-date -format o)] `"$($request.HttpMethod) $($request.Url) HTTP/$($request.ProtocolVersion)`" $($response.StatusCode) $($buffer.Length)"
    RSLog $message
    $configuration.log_writer.WriteLine($message)
    $configuration.log_writer.Flush()
    $response.Dispose()
}


function RSDebug ($message) {
    if ($configuration.ShowDebug) {
        $configuration.HostProxy.UI.WriteDebugLine($message)
    }
}

function RSLog ($message) {
    if ($configuration.LogToConsole) {
        $configuration.HostProxy.UI.WriteLine($message)
    }
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
        # Used from the InspectCommand function. PSScriptAnalyzer is angry with them, but don't delete :)
        $seen = New-Object System.Collections.ArrayList
        $global_scope = [psmoduleinfo]::new($true)
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
                    $check_command = $global_scope.Invoke( { param([string]$name); get-command $name }, $name)
                    #$check_command = Get-Command $name -ErrorAction 'Stop'
                    Write-Debug "$name retrieved from global scope"       
                }
                catch { 
                    # Still nothing, which probably means that this command came from a module within a module like
                    # StorageScripts which is automatically loaded by the Storage module, but is not importable or
                    # visible otherwise. We don't need to load these - the modules should take care of that
                    # themselves.
                    $skip_processing = $true
                    Write-Debug "Unable to find $name"
                }
            }
        }
    }

    if (-not $skip_processing) {
        Write-Debug "CommandType is $($check_command.CommandType)"
        Write-Debug "Source is $($check_command.Source)"
    
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
                Write-Debug "Looking for variable $var_name in global scope"
                try {
                    $var = Get-Variable -Name $var_name -Scope 'Global' -ErrorAction 'Stop'
                    $var = $true
                }
                catch {
                    $var = $false
                }
                if ($var -and $var_name -notin $variable_blacklist -and -not $check_command.Source) {
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
        #$runspace_pool = [runspacefactory]::CreateRunspacePool(1, $MaximumThreads, $session_state, $Host)
        $runspace_pool = [runspacefactory]::CreateRunspacePool($session_state)
        [void]$runspace_pool.SetMaxRunspaces($MaximumThreads)
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
        $c.Configuration.LogWriter.Close()
        $listener_table.Remove($c)
    }
}


function New-UrlAclReservation ($prefix_string) {
    if ($IsWindows) {
        netsh http add urlacl url=$prefix_string user=$($env:USERDOMAIN)\$($env:USERNAME)

        # Store the urlacl's created by this module so we can help clean them up later if need be
        $storage_path = join-path (split-path (Get-Command publish-command).Module.Path) -ChildPath "Persist" -AdditionalChildPath "urlacls.txt"
        if (-not (Test-Path $storage_path)) { New-Item -Path $storage_path -Force | Out-Null }
        Add-Content -Path $storage_path -Value $prefix_string
    }
    else {
        Write-Warning "The switch AddUrlAcl is only supported on Windows!"
    }
}


function Remove-PSApiUrlAclReservation ($prefix_string) {
    <#
    .DESCRIPTION
    Aids in removing URL reservations made by this module. Best used in conjunction with Get-PSApiUrlAclReservation
    
    .PARAMETER prefix_string
    The prefix string to remove.
    
    .EXAMPLE
    Get-PSApiUrlAclReservation | foreach {Remove-PSApiUrlAclReservation $_}
    #>
    
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
    <#
    .DESCRIPTION
    Shows URL reservations performed by this module. Can be used in conjunction with Remove-PSApiUrlAclReservation to clean up.
    
    .EXAMPLE
    Get-PSApiUrlAclReservation | foreach {Remove-PSApiUrlAclReservation $_}
    #>
    
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


function New-PSApiCorsPolicy {
    <#
    .SYNOPSIS
    Creates a policy for Cross-Origin Resource Sharing to pass to PSApi.
    
    .DESCRIPTION
    Creates a policy for Cross-Origin Resource Sharing to pass to PSApi. Note that all CORS elements are implemented, even those that do not make any sense to PSApi currently. To get a better understanding of CORS read up on the documentation at https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS.
    
    .PARAMETER Allow-Origin
    Sets one or more values for the Access-Control-Allow-Origin header. Origin will be checked at request time, and only the calling host will be returned in the Access-Control-Allow-Origin header.
    
    .PARAMETER Allow-Credentials
    Sets the value for the Access-Control-Allow-Credentials header.
    
    .PARAMETER Expose-Headers
    Sets the value for the Access-Control-Expose-Headers header.
    
    .PARAMETER Max-Age
    Sets the value for the Access-Control-Max-Age header.
    
    .PARAMETER Allow-Methods
    Sets one or more values for the Access-Control-Allow-Methods header.
    
    .PARAMETER Allow-Headers
    Sets one or more values for the Access-Control-Allow-Headers header.
    
    .EXAMPLE
    # I just want CORS to go away
    PS > $cors_policy = New-PSApiCorsPolicy -Allow-Origin '*'
    PS > Publish-Command My-Command -CorsPolicy $cors_policy
    
    .NOTES
    General notes
    #>
    
    [CmdletBinding()]
    param (
        [string[]]${Allow-Origin},
        [switch]${Allow-Credentials},
        [string[]]${Expose-Headers},
        [int]${Max-Age},
        [string[]]${Allow-Methods},
        [string[]]${Allow-Headers}
    )
    [PSCustomObject]$output = @{ }
    $psboundparameters.GetEnumerator() | ForEach-Object {
        if ($_.Value.Count -gt 1) {
            $val = $_.Value -join ", "
        }
        else {
            $val = $_.Value[0]
        }
        $output['Access-Control-' + $_.Key] = $val
    }
    $output
}
