param($TeamNumber = (Get-Date -Format yyMMddHHMMssff), $FlagsId = 777)

$envParams = @{
	ResourceGroupName = ('x33fcon-' + $TeamNumber)
	ADFQDN            = 'x33fcon.local'
	ParametersFileId  = $FlagsId
	DetailedLocalFile = $true
	SkipWebApp        = $true
	FlagPrefix        = 'x33fcon'
}
.\Start-LudusMagnus.ps1 @envParams 