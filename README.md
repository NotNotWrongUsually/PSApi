# PSApi

## Tl;dr
The PSApi module takes a function or cmdlet from your current session and publishes it as a webservice. The command used for this is `Publish-Command`. It works like this:

![Screenshot](https://i.imgur.com/ngPtd3R.png)

## Installation instructions
The module is published to the Powershell Gallery, so install it with:
    
    Install-Module PSApi -Scope "CurrentUser"

Scope to taste, of course.

The module requires PowerShell Core, and is tested on both Linux and Windows. Testing has been done on 6.2.3, but I believe nothing should prevent it from working from 6.0 and onwards.

## Long description
`Publish-Command` is supplied with relatively sane defaults. Using these, your command will be exposed at `http://localhost/PSApi/<your-command>` using port 80, a maximum of five background threads, dropping access logs in your current directory. The url prefix wildcard "+" is used for hostname by default, but can be overridden with the `Hostname` parameter. Consult the [Urlprefix documentation](https://docs.microsoft.com/en-us/windows/win32/http/urlprefix-strings) for more information.

Using parameters for the command you can modify served path, port, hostname, logging location etc. Refer to the built-in help for Publish-Command for more information about the options.

Parameters for a published command are supplied in the url query string, or - using POST - a JSON payload. Url encoded form data as supplied with an HTML form will be interpreted correctly as well for both GET and POST (example 3 below shows using a form to supply parameters).

The next examples require the command Get-Process to have been published. You can do so with:

    PS > Publish-Command Get-Process

These examples list a command and the equivalent url for retrieving it:

    Command:    Get-Process -Name "notepad"
        URL:    http://myhostname/PSApi/Get-Process?name=notepad

In some cases you may want to supply an array of strings. This can be done in the following way.

    Command:    Get-Process -Name "notepad", "chrome"
        URL:    http://myhostname/PSApi/Get-Process?name=notepad&name=chrome

Switch parameters are supplied in the following way (note the '=' sign after the parameter):

    Command:    Get-Process -Name "notepad" -FileVersionInfo
        URL:    http://myhostname/PSApi/Get-Process?name=notepad&FileVersionInfo=

Please note that parameters will always be strings when they arrive at your function. In most cases PowerShell's type coercion will make sure things are fine. Ambiguity can occur in certain cases, usually involving constructors for .NET objects (consider supplying the parameters "100", "100" to a class that has overloads for both `<string>`, `<int>` and `<string>`, `<string>`). If you run into bugs with this make sure you specify type for the parameters in your function and you should be fine.

When a function has been published, changes to it in your local shell will not propagate to the published one, since it is running in a separate runspace. Either unpublish/republish the function, or run `Publish-Command` for it again, including the `-Force` switch (this is essentially the same us unpublish/republish).

If an exception is raised during execution of a published command a custom HTTP 500 page will be returned. By default this is HTML, but this behaviour can be overridden with the switch parameter `-JSONErrorMode`.

## Running without Administrator/Root
On Windows, Administrator rights are needed to create an http listener. On Linux superuser rights are needed to listen to anything below port 1024.
    
It is possible on Windows to reserve a URL for non-administrator use. This is the recommended way to publish a command on a more permanent basis. The module includes support for this via the `-AddUrlAcl` switch. From an elevated shell use `Publish-Command` as you normally would, but include the switch.
Instead of publishing the command, a URL reservation will be created. After this you can run Publish-Command with the same parameters (except the switch) from a non-elevated shell.

The module tries to keep track of which URL reservations it has made. The two commands Get-PSApiUrlAclReservation and Remove-PSApiUrlAclReservation are intended to help you manage these if you wish to clean up at a later point.

## Logging
An access log is automatically created on a per-command basis. By default this will go into the directory you were in when you published the command. The log adheres to Common Log Format.

## Return types from your command
If a published function emits certain outputs some special handling is applied:

#### [XML]
is turned into a string by using the OuterXml property of the object. ContentType is set to text/xml.

#### [System.Drawing.Bitmap]
will be converted to png format and presented in the browser. ContentType is set to image/png.

#### [Microsoft.Powershell.Commands.HtmlWebResponseObject]
This is what Invoke-WebRequest gets back. It will be turned into a string by using the content property, so only the actual html is passed on. ContentType is set to text/html.

#### [String]
will be sent with a content type of text/html. For an exception refer to the note on JSON below.

**JSON:** There is no specific JSON type. Even content created with ConvertTo-Json is just listed as [String]. To present the correct content-type for JSON a test is performed on [String] objects. If an object can be be piped to ConvertFrom-Json without raising an exception the content-type will be set to application/json. The Test-Json cmdlet is not used for this as it appears utterly broken from testing.

#### Everything else
Anything that is not one of the above types will be stringified with the Out-String cmdlet and set to a content-type of text/plain. Notably this means that most things will look exactly like they do in the Powershell console.

## Unpublishing commands
The module includes an Unpublish-Command function to stop publishing functions. Quitting the shell works too.

## Aliases
pcm, upcm, gpcm is included for Publish-Command, Unpublish-Command, Get-PublishedCommand respectively.

## Is it safe?
Care has been taken to avoid injection attacks by never parsing command inputs from anything but the HTTPListener path defined by the user. A number of scenarios like trying to inject code into strings with $(), semicolons, etc. have also been tested. Though nothing has been discovered so far, it is not adviced to expose any cmdlet to the Internet for the time being. Should you discover a way to exploit this module please create an issue at https://github.com/NotNotWrongUsually/PSApi so the matter can be addressed appropriately!
    
All that being said: *Any disaster you cause by using this module is entirely on you!*

## Examples

### Example 1

Creating a simple monitoring API showing the processes using most CPU time
 
    function Get-HighCpuConsumers ($Top=5) {
        Get-Process | Sort-Object CPU -Descending |
        Select-Object Name, CPU, StartTime -first $Top |
        ConvertTo-Json
    }

    PS > Publish-Command Get-HighCpuConsumers

Going to `http://localhost/PSApi/Get-HighCpuConsumers?number=2` will now hand back JSON like the following

    [
        {
            "Name": "System",
            "CPU": 18658.296875,
            "StartTime": "2019-09-13T16:29:03.564575+02:00"
        },
        {
            "Name": "services",
            "CPU": 6294.734375,
            "StartTime": "2019-09-13T16:29:06.6348728+02:00"
        }
    ]

### Example 2

Serving an image.

    function Get-Image {
        New-Object System.Drawing.Bitmap -ArgumentList "C:\some_picture.jpg"
    }

Going to `http://localhost/PSApi/Get-Image` will display the picture. The image types that can be loaded in by [System.Drawing.Bitmap](https://docs.microsoft.com/en-us/dotnet/api/system.drawing.bitmap?view=netcore-2.2) are all supported for input, but output will always be converted to .PNG.

*(Note that on Linux `libgdiplus` is needed before this example works)*

### Example 3

Using an HTML form to gather input for the command

    function Show-Name ($Name) {
        if (-not $Name) {
            # Display a form
            @'
            <html>
              <head>
                <title>A form!</title>
              </head>
              <body>
                <h1>What is your name?</h1>
                <form action="http://localhost/PSApi/Show-Name" method="GET">
                  Name<br>
                  <input type="text" name="Name"><br>
                  <input type="submit" value="Submit">
                </form>
              </body>
            </html>
    '@ 
        } else {
            # This will only run if name was supplied
            "The entered name was $Name"
        }
    }

### Example 4

Setting up CORS to accept POST requests with specific content-type (e.g. 'application/json') (this is only ever needed if you want a website from a different host accessing your command)

    $cors = New-PSApiCorsPolicy -Allow-Origin '*' -Allow-Methods 'POST, GET' -Allow-Headers 'Content-Type'
    Publish-Command <myfunction> -CorsPolicy $cors