param(
    $ResourceGroupName = ('LudusMagnus-{0:yyyyMMddHHmm}' -f (Get-Date)),
    $Location = 'westeurope'
)

$Version = '0.0.0.2'

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
AKA get a coffee until the webapp will pop open.

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

# Types and constants
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

# Prepare the deployment parameters
$publicIP = (Invoke-WebRequest -Uri 'https://api.ipify.org/?format=json').Content | ConvertFrom-Json | Select-Object -ExpandProperty ip
$deploymentParams = @{
    TemplateUri             = $templateBaseUrl + '/azuredeploy.json'
    ResourceGroupName       = $ResourceGroupName
    Name                    = ('LudusMagnusDeployment-{0:yyyyMMddHHmm}' -f (Get-Date))
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

# Add the passwords as deployment parameters
$flags | Select-Object -Property *Password* | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name | ForEach-Object {
    $deploymentParams.Add($_, ((($flags | Select-Object -ExpandProperty $_).Value) | ConvertTo-SecureString -AsPlainText -Force))
}

# Verify the ResourceGroup exists
if (-not (Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue)) {
    New-AzResourceGroup -Name $resourceGroupName -Location $Location | Out-Null
}

# Start the deployment
$deploymentResult = New-AzResourceGroupDeployment @deploymentParams
if ($deploymentResult.ProvisioningState -eq 'Succeeded') {

    # Encrypt the parameters
    $params = [System.Net.WebUtility]::UrlEncode(
        ('{0}_{1}_{2}_{3}' -f `
            ($deploymentResult.Outputs.Values)[0].Value, ($deploymentResult.Outputs.Values)[1].Value,
            $flags['VmAdminPassword'], $templateParamsId
        )
    )
    $encryptedParams = [Encrypt]::EncryptString($params)

    # Open the default browser on the WebApp's scoring page
    Start-Process ('https://{0}/?s={1}' -f ($deploymentResult.Outputs.Values)[2].Value, $encryptedParams)

}
else {
    # Deployment error!
    $deploymentResult
}
