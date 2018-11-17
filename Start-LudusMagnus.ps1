param(
    $ResourceGroupName = ('LudusMagnus-{0:yyyyMMddHHmm}' -f (Get-Date)),
    $Location = 'westeurope'
)

$tamplateBaseUrl = 'https://raw.githubusercontent.com/martin77s/LudusMagnus/master'
$publicIP = (Invoke-WebRequest -Uri 'https://api.ipify.org/?format=json').Content | ConvertFrom-Json | Select-Object -ExpandProperty ip
$deploymentParams = @{
    TemplateUri             = $tamplateBaseUrl + '/azuredeploy.json'
    ResourceGroupName       = $ResourceGroupName
    Name                    = ('LudusMagnusDeployment-{0:yyyyMMddHHmm}' -f (Get-Date))
    Force                   = $true
    Verbose                 = $true
    ErrorVariable           = 'deploymentErrors'
    DeploymentDebugLogLevel = 'None' # All | None | RequestContent | ResponseContent
    ClientAllowedIP         = '{0}/32' -f $publicIP
}

# Add the flags values as deployment parameters
$rand = Get-Random -Minimum 0 -Maximum 9; $rand = ''
$flags = ((Invoke-WebRequest -Uri (($tamplateBaseUrl + '/azuredeploy.parameters{0}.json') -f $rand)).Content | ConvertFrom-Json).parameters
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
}
else {
    $deploymentResult
}
