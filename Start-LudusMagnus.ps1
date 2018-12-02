param(
    $ResourceGroupName = ('LudusMagnus-{0:yyyyMMddHHmm}' -f (Get-Date)),
    $Location = 'westeurope'
)

$Version = '0.0.0.3'

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
            Sort-Object {Get-Random})[0..$Length] -join ''
    ($Prefix + $Suffix).Substring(0, $Length)
}


# Prepare the deployment parameters
$deploymentName = 'LudusMagnus-{0:yyyyMMddHHmm}' -f (Get-Date)
$vmAdminPassword = Initialize-LudusMagnusPassword -Prefix 'P@5z'
$publicIP = (Invoke-WebRequest -Uri 'https://api.ipify.org/?format=json').Content | ConvertFrom-Json | Select-Object -ExpandProperty ip
$deploymentParams = @{
    TemplateUri             = $templateBaseUrl + '/azuredeploy.json'
    ResourceGroupName       = $ResourceGroupName
    Name                    = $deploymentName
    VmAdminPassword         = ($vmAdminPassword | ConvertTo-SecureString -AsPlainText -Force)
    ClientAllowedIP         = '{0}/32' -f $publicIP
    ErrorVariable           = 'deploymentErrors'
    DeploymentDebugLogLevel = 'None' # All | None | RequestContent | ResponseContent
    Force                   = $true
    Verbose                 = $true
}

# Add the flags values as deployment parameters
$templateParamsId = Get-Random -Minimum 0 -Maximum 99
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
$iCount = 1; $maxWait = 45
try {
    $deploymentJob = New-AzResourceGroupDeployment @deploymentParams -AsJob
    :waitDeployment do {
        Write-Verbose -Message "Waiting for the deployment to complete... ($iCount)" -Verbose
        Start-Sleep -Seconds 60
        $iCount++
        if ($iCount -ge $maxWait) { break waitDeployment }
    } while (
        (Get-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -Name $deploymentName).ProvisioningState -eq 'Running'
    )
    $deploymentResult = Get-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -Name $deploymentName
    if ($deploymentResult.ProvisioningState -eq 'Succeeded') {

        # Encrypt the parameters
        $params = [System.Net.WebUtility]::UrlEncode(
            ('{0}_{1}_{2}_{3}' -f `
                ($deploymentResult.Outputs["ipAddress"].Value),
                ($deploymentResult.Outputs["jumpBoxAdmin"].Value),
                $vmAdminPassword, $templateParamsId
            )
        )
        $encryptedParams = [Encrypt]::EncryptString($params)

        # Open the default browser with a custom link to the WebApp
        $url = 'https://{0}/?s={1}' -f ($deploymentResult.Outputs["webAppFqdn"].Value), $encryptedParams
        $htmlPath = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "$ResourceGroupName.htm"
        @"
        Use the following url to get the deployment details and start the assesment:<br/>
        <a href='$url'>$url</a><br/><br/>
"@ | Set-Content -Path $htmlPath
        Start-Process -FilePath $htmlPath
        Write-Host @"
Deployment completed!
Use the following url to get the deployment details and start the assesment:
$url
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