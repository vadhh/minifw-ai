rule Detect_JS_Execution_Commands
{
    meta:
        description = "Detects JavaScript code containing execution commands"
        author = "YourName"
        date = "2024-07-06"
        version = "1.0"

    strings:
        $eval = /eval\s*\(/
        $function = /new\s+Function\s*\(/
        $setTimeout = /setTimeout\s*\(/
        $setInterval = /setInterval\s*\(/
        $document_write = /document\.write\s*\(/
        $execCommand = /execCommand\s*\(/
        $unescape = /unescape\s*\(/
        $atob = /atob\s*\(/
        $decodeURIComponent = /decodeURIComponent\s*\(/
        $activeXObject = /ActiveXObject\s*\(/
        $script = /<script.*>.*<\/script>/i
        
    condition:
        any of ($eval, $function, $setTimeout, $setInterval, $document_write, $execCommand, $unescape, $atob, $decodeURIComponent, $activeXObject, $script)
}

rule Detect_Python_Execution_Commands
{
    meta:
        description = "Detects Python code containing execution commands"
        author = "YourName"
        date = "2024-07-06"
        version = "1.0"

    strings:
        $eval = /eval\s*\(/
        $exec = /exec\s*\(/
        $os_system = /os\.system\s*\(/
        $subprocess = /subprocess\.Popen\s*\(/
        $execfile = /execfile\s*\(/
        $compile = /compile\s*\(/
        
    condition:
        any of ($eval, $exec, $os_system, $subprocess, $execfile, $compile)
}

rule Detect_PHP_Execution_Commands
{
    meta:
        description = "Detects PHP code containing execution commands"
        author = "YourName"
        date = "2024-07-06"
        version = "1.0"

    strings:
        $eval = /eval\s*\(/
        $exec = /exec\s*\(/
        $shell_exec = /shell_exec\s*\(/
        $system = /system\s*\(/
        $passthru = /passthru\s*\(/
        $popen = /popen\s*\(/
        $proc_open = /proc_open\s*\(/
        
    condition:
        any of ($eval, $exec, $shell_exec, $system, $passthru, $popen, $proc_open)
}

rule Detect_Ruby_Execution_Commands
{
    meta:
        description = "Detects Ruby code containing execution commands"
        author = "YourName"
        date = "2024-07-06"
        version = "1.0"

    strings:
        $eval = /eval\s*\(/
        $exec = /`.*`/
        $system = /system\s*\(/
        $open = /open\s*\(/
        $IO_popen = /IO\.popen\s*\(/
        
    condition:
        any of ($eval, $exec, $system, $open, $IO_popen)
}

rule Detect_Perl_Execution_Commands
{
    meta:
        description = "Detects Perl code containing execution commands"
        author = "YourName"
        date = "2024-07-06"
        version = "1.0"

    strings:
        $eval = /eval\s*\(/
        $exec = /`.*`/
        $system = /system\s*\(/
        $open = /open\s*\(/
        $qx = /qx\s*\(/
        
    condition:
        any of ($eval, $exec, $system, $open, $qx)
}

rule Detect_PowerShell_Execution_Commands
{
    meta:
        description = "Detects PowerShell scripts containing execution commands"
        author = "YourName"
        date = "2024-07-06"
        version = "1.0"

    strings:
        $invoke_expression = /Invoke-Expression/
        $iex = /iex/
        $start_process = /Start-Process/
        $invoke_command = /Invoke-Command/
        $new_object = /New-Object\s+System\.Management\.Automation\.PSObject/
        
    condition:
        any of ($invoke_expression, $iex, $start_process, $invoke_command, $new_object)
}

rule Detect_ShellScript_Execution_Commands
{
    meta:
        description = "Detects Shell script code containing execution commands"
        author = "YourName"
        date = "2024-07-06"
        version = "1.0"

    strings:
        $eval = /eval\s+/
        $exec = /exec\s+/
        $backticks = /`.*`/
        $system = /system\s*\(/
        $sh = /sh\s+-c/
        
    condition:
        any of ($eval, $exec, $backticks, $system, $sh)
}

