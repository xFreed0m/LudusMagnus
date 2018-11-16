# Login-AzAccount
# Get-AzSubscription
# Select-AzSubscription -Subscription '00000000-0000-0000-0000-000000000000'

### DO NOT CHANGE ANYTHING BELOW THIS LINE ###
$tamplateBaseUrl = 'https://raw.githubusercontent.com/martin77s/LudusMagnus/master'
$location = 'westeurope'
$publicIP = (Invoke-WebRequest -Uri 'https://api.ipify.org/?format=json').Content | ConvertFrom-Json | Select-Object -ExpandProperty ip
$resourceGroupName = 'Sandbox'
$deploymentName = '{0}-{1:yyyyMMddHHmm}' -f $resourceGroupName, (Get-Date)
$deploymentParams = @{
    TemplateUri             = $tamplateBaseUrl + '/azuredeploy.json'
    ResourceGroupName       = $resourceGroupName
    Name                    = $deploymentName
    Force                   = $true
    Verbose                 = $true
    ErrorVariable           = 'deploymentErrors'
    DeploymentDebugLogLevel = 'None' # All | None | RequestContent | ResponseContent
    ClientAllowedIP         = '{0}/32' -f $publicIP
}

# Add the flags
$rand = Get-Random -Minimum 0 -Maximum 9; $rand = ''
$flags = ((Invoke-WebRequest -Uri (($tamplateBaseUrl + '/azuredeploy.parameters{0}.json') -f $rand)).Content | ConvertFrom-Json).parameters
$flags | Select-Object -Property Flag*Value | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name | ForEach-Object {
    $deploymentParams.Add($_, ($flags | Select-Object -ExpandProperty $_).Value)
}

# Add the passwords
$flags | Select-Object -Property *Password* | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name | ForEach-Object {
    $deploymentParams.Add($_, ((($flags | Select-Object -ExpandProperty $_).Value) | ConvertTo-SecureString -AsPlainText -Force))
}

# Verify the ResourceGroup exists
if (-not (Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue)) {
    New-AzResourceGroup -Name $resourceGroupName -Location $location
}

# Enable debugging messages
#$DebugPreference = "Continue"

# Start the deployment
$deploymentResult = New-AzResourceGroupDeployment @deploymentParams
$deploymentResult
if ($deploymentResult.ProvisioningState -eq 'Succeeded') {
    ($deploymentResult.Outputs.Values)[0].Value
}
