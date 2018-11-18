param(
    $ResourceGroupName = ('LudusMagnus-{0:yyyyMMddHHmm}' -f (Get-Date)),
    $Location = 'westeurope'
)

$Version = '0.0.0.1'

Write-Host @"

[+][+][+][+][+][+][+][+][+][+][+][+][+][+][+][+][+]
[+]                                             [+]
[+]          Welcome to LudusMagnus!            [+]
[+]                                             [+]
[+]                                .-.          [+]
[+]                               {{@}}         [+]
[+]               <>               8@8          [+]
[+]             .::::.             888          [+]
[+]         @\\/W\/\/W\//@         8@8          [+]
[+]          \\/^\/\/^\//     _    )8(    _     [+]
[+]           \_O_<>_O_/     (@)__/8@8\__(@)    [+]
[+]      ____________________ '~"-=):(=-"~'     [+]
[+]     |<><><>  |  |  <><><>|     |.|          [+]
[+]     |<>      |  |      <>|     |M|          [+]
[+]     |<>      |  |      <>|     |'|          [+]
[+]     |<>   .--------.   <>|     |.|          [+]
[+]     |     |   ()   |     |     |S|          [+]
[+]     |_____| (O\/O) |_____|     |'|          [+]
[+]     |     \   /\   /     |     |.|          [+]
[+]     |------\  \/  /------|     |R|          [+]
[+]     |       '.__.'       |     |'|          [+]
[+]     |        |  |        |     |.|          [+]
[+]     :        |  |        :     |F|          [+]
[+]      \<>     |  |     <>/      |'|          [+]
[+]       \<>    |  |    <>/       |.|          [+]
[+]        \<>   |  |   <>/        |S|          [+]
[+]         \<>  |  |  <>/         |'|          [+]
[+]          \-. |  | .-/          \ /          [+]
[+]              '--'               .           [+]
[+]version: $version                            [+]
[+][+][+][+][+][+][+][+][+][+][+][+][+][+][+][+][+]

      Creating the arena might take some time...
      prepare your weapons until the arena master
      will call your name.
      AKA get a coffee until the webapp will pop open.

Brought to you by @martin77s & @x_Freed0m
"@ -Foreground darkcyan -Background black



$templateBaseUrl = 'https://raw.githubusercontent.com/martin77s/LudusMagnus/master'
$publicIP = (Invoke-WebRequest -Uri 'https://api.ipify.org/?format=json').Content | ConvertFrom-Json | Select-Object -ExpandProperty ip
$deploymentParams = @{
    TemplateUri             = $templateBaseUrl + '/azuredeploy.json'
    ResourceGroupName       = $ResourceGroupName
    Name                    = ('LudusMagnusDeployment-{0:yyyyMMddHHmm}' -f (Get-Date))
    Force                   = $true
    Verbose                 = $true
    ErrorVariable           = 'deploymentErrors'
    DeploymentDebugLogLevel = 'None' # All | None | RequestContent | ResponseContent
    ClientAllowedIP         = '{0}/32' -f $publicIP
}

# Add the flags values as deployment parameters
$templateParametersUri = ($tamplateBaseUrl + '/azuredeploy.parameters/azuredeploy.parameters{0}.json') -f (Get-Random -Minimum 0 -Maximum 99)
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
    @'
    To RDP the Jumpbox use the following details:
    IPAddress: {0}
    UserName: {1}
    Password: {2}
'@ -f ($deploymentResult.Outputs.Values)[0].Value, ($deploymentResult.Outputs.Values)[1].Value, $flags['VmAdminPassword']

    # Todo: Open the default browser on the WebApp's scoring page (with the deployment return values as paramters)
    $encodedParams = [System.Net.WebUtility]::UrlEncode(
        '{0} _ {1} _ {2}' -f ($deploymentResult.Outputs.Values)[0].Value, ($deploymentResult.Outputs.Values)[1].Value, $flags['VmAdminPassword']
    )
    Start-Process ('http://google.com?q={0}' -f $encodedParams)
}
else {
    $deploymentResult
}
