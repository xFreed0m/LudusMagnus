param(
    [string] $ResourceGroupName = ('LudusMagnus-{0:yyyyMMddHHmm}' -f (Get-Date)),

    [string] $Location = 'westeurope',

    [ValidatePattern('\.local$')]
    [string] $ADFQDN = 'LudusMagnus.local',

    [string] $ParametersFileId = $null,

    [switch] $DetailedLocalFile,

    [switch] $SkipWebApp,
	
    [switch] $Promiscuous,
	
	[ValidatePattern('\w+')]
	[string] $FlagPrefix = 'Flag'
)

$Version = '0.0.0.7'

Write-Host @"

[+][+][+][+][+][+][+][+][+][+][+][+][+][+][+][+][+][+][+][+]
[+]                                                      [+]
[+]              Welcome to LudusMagnus!                 [+]
[+]                                                      [+]
[+]                                     .-.              [+]
[+]                                    {{@}}             [+]
[+]                   <>                8@8              [+]
[+]                 .::::.              888              [+]
[+]             @\\/W\/\/W\//@          8@8              [+]
[+]              \\/^\/\/^\//      _    )8(    _         [+]
[+]               \_O_<>_O_/      (@)__/8@8\__(@)        [+]
[+]          ____________________  '~"-=):(=-"~'         [+]
[+]         |<><><>  |  |  <><><>|      |.|              [+]
[+]         |<>      |  |      <>|      |M|              [+]
[+]         |<>      |  |      <>|      |'|              [+]
[+]         |<>   .--------.   <>|      |.|              [+]
[+]         |     |   ()   |     |      |S|              [+]
[+]         |_____| (O\/O) |_____|      |'|              [+]
[+]         |     \   /\   /     |      |.|              [+]
[+]         |------\  \/  /------|      |R|              [+]
[+]         |       '.__.'       |      |'|              [+]
[+]         |        |  |        |      |.|              [+]
[+]         :        |  |        :      |F|              [+]
[+]          \<>     |  |     <>/       |'|              [+]
[+]           \<>    |  |    <>/        |.|              [+]
[+]            \<>   |  |   <>/         |S|              [+]
[+]             \<>  |  |  <>/          |'|              [+]
[+]              \-. |  | .-/           \ /              [+]
[+]               \  '--'  /             V               [+]
[+]                \______/                              [+]
[+]                                                      [+]
[+] Version: $version                                     [+]
[+]                                                      [+]
[+][+][+][+][+][+][+][+][+][+][+][+][+][+][+][+][+][+][+][+]

Creating the arena might take some time...
Prepare your weapons until the arena master calls your name
AKA, get a coffee until your browser opens.

Brought to you by @martin77s & @x_Freed0m

"@ -Foreground darkcyan -Background black

# Verify latest version
$content = (Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/martin77s/LudusMagnus/master/Start-LudusMagnus.ps1').Content
if ($content -match "(?m)\`$Version = '(?<version>.*)'$") {
    $onlineVersion = $Matches['version']
    if ($Version -ne $onlineVersion) {
        $content | Out-File -FilePath $MyInvocation.MyCommand.Path -Force
        Write-Host 'Updated version detected and downloaded, please run this script again'
        exit
    }
}

# Types, constants and helper functions
$source = @'
public static class Encrypt {
    public static string EncryptString(string encryptString) {
        string encryptionKey = "a361b2ffffd211d1aa4b00c04fd7d83a";
        byte[] salt = System.Text.Encoding.UTF8.GetBytes("*LUDUSMAGNUS*");
        byte[] clearBytes = System.Text.Encoding.Unicode.GetBytes(encryptString);
        using (System.Security.Cryptography.Aes encryptor = System.Security.Cryptography.Aes.Create()) {
            System.Security.Cryptography.Rfc2898DeriveBytes pdb = new System.Security.Cryptography.Rfc2898DeriveBytes(encryptionKey , salt);
            encryptor.Key = pdb.GetBytes(32);
            encryptor.IV = pdb.GetBytes(16);
            using (System.IO.MemoryStream ms = new System.IO.MemoryStream()) {
                using (System.Security.Cryptography.CryptoStream cs = new System.Security.Cryptography.CryptoStream(
                    ms , encryptor.CreateEncryptor() , System.Security.Cryptography.CryptoStreamMode.Write)) {
                    cs.Write(clearBytes , 0 , clearBytes.Length);
                    cs.Close();
                }
                encryptString = System.Convert.ToBase64String(ms.ToArray());
            }
        }
        return encryptString;
    }
}
'@
Add-Type -TypeDefinition $source
$templateBaseUrl = 'https://raw.githubusercontent.com/martin77s/LudusMagnus/master'
function Initialize-LudusMagnusPassword {
    param([string]$Prefix = '', $Length = 24)
    $Suffix = ([char[]]([char]33..[char]95) + ([char[]]([char]97..[char]126)) + 0..9 |
        Sort-Object { Get-Random })[0..$Length] -join ''
    ($Prefix + $Suffix).Substring(0, $Length)
}

# Prepare the deployment parameters
$deploymentName = 'CTF-{0:yyyyMMddHHmmssff}' -f (Get-Date)
$vmAdminPassword = Initialize-LudusMagnusPassword -Prefix 'P@5z'

if($Promiscuous) {
	$clientAllowedIP = '0.0.0.0/0'
} else {
	try {
		$clientAllowedIP = '{0}/32' -f (
			(Invoke-WebRequest -Uri 'https://api.ipify.org/?format=json').Content | ConvertFrom-Json | Select-Object -ExpandProperty ip
		)
	} catch {
		$clientAllowedIP = '0.0.0.0/0'
	}
}

$deploymentParams = @{
    TemplateUri             = $templateBaseUrl + '/azuredeploy.json'
    ResourceGroupName       = $ResourceGroupName
    Name                    = $deploymentName
    ClientAllowedIP         = $clientAllowedIP
    VmAdminPassword         = ($vmAdminPassword | ConvertTo-SecureString -AsPlainText -Force)
    DomainName              = $ADFQDN
	FlagPrefix              = $FlagPrefix
    DeployWebApp            = if ($SkipWebApp) { 0 } else { 1 }
    ErrorVariable           = 'deploymentErrors'
    DeploymentDebugLogLevel = 'None' # All | None | RequestContent | ResponseContent
    Force                   = $true
    Verbose                 = $true
}

# For debugging only..
Write-Host $vmAdminPassword  -ForegroundColor Black

# Add the flags values as deployment parameters
if ([string]::IsNullOrEmpty($ParametersFileId)) {
    $templateParamsId = Get-Random -Minimum 0 -Maximum 99
}
else {
    $templateParamsId = $ParametersFileId
}
$templateParametersUri = ($templateBaseUrl + '/azuredeploy.parameters/azuredeploy.parameters{0}.json') -f $templateParamsId
$flags = ((Invoke-WebRequest -Uri ($templateParametersUri)).Content | ConvertFrom-Json).parameters
$flags | Select-Object -Property Flag*Value | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name | ForEach-Object {
    $deploymentParams.Add($_, ($flags | Select-Object -ExpandProperty $_).Value)
}

# Verify the ResourceGroup exists
if (-not (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue)) {
    New-AzResourceGroup -Name $ResourceGroupName -Location $Location | Out-Null
}

# Start the deployment
$iCount = 1; $maxWait = 35
try {
    $deploymentJob = New-AzResourceGroupDeployment @deploymentParams -AsJob
	$global:__job = $deploymentJob
	
    :waitDeployment do {
        Write-Verbose -Message "Waiting for the deployment to complete... ($iCount)" -Verbose
        Start-Sleep -Seconds 60
        $iCount++
        if ($iCount -ge $maxWait) { break waitDeployment }
    } while (
        'Failed', 'Running' -contains (Get-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -Name $deploymentName).ProvisioningState
    )
    $deploymentResult = Get-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -Name $deploymentName
    if ($deploymentResult.ProvisioningState -eq 'Succeeded') {
        $htmlPath = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "$ResourceGroupName.htm"
        if ($DetailedLocalFile) {
            $content = @"
                <h1>Use the following details to start the assessment:</h1>
                <table border=1>
                    <tr><td>The Jumpbox IP is: </td><td>{0}</td></tr>
                    <tr><td>The UserName is: </td><td>{1}</td></tr>
                    <tr><td>The Password is: </td><td>{2}</td></tr>
                    <tr><td>ResourceGroup Name: </td><td>{3}</td></tr>
                </table>
"@ -f ($deploymentResult.Outputs["ipAddress"].Value),
            ($deploymentResult.Outputs["jumpBoxAdmin"].Value),
            [System.Web.HttpUtility]::HtmlEncode($vmAdminPassword), $ResourceGroupName
        }
        else {
            # Encrypt the parameters
            $params = [System.Net.WebUtility]::UrlEncode(
                ('{0}|||{1}|||{2}|||{3}' -f `
                    ($deploymentResult.Outputs["ipAddress"].Value),
                    ($deploymentResult.Outputs["jumpBoxAdmin"].Value),
                    $vmAdminPassword, $templateParamsId
                )
            )
            $encryptedParams = [Encrypt]::EncryptString($params)
            $url = 'https://{0}/?s={1}' -f ($deploymentResult.Outputs["webAppFqdn"].Value), $encryptedParams
            $content = @"
                Use the following url to get the deployment details and start the assessment:<br/>
                <a href='$url'>$url</a><br/><br/>
"@
        }
        # Open the default browser with the environment details or link
        $content | Set-Content -Path $htmlPath
        Start-Process -FilePath $htmlPath
        Write-Host @"
Deployment completed!
Use the details in the following file to get the deployment details and start the assessment:
$htmlPath
"@ -Foreground darkcyan -Background black
    }
    else {
        # Deployment error!
        $deploymentResult
    }
}
catch {
    $_.Exception.GetType().FullName
    $_.Exception.Message
}

# Cleanup
if ($deploymentJob.State -eq 'Completed') { Remove-Job -Job $deploymentJob }