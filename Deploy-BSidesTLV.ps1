param($TeamNumber = (Get-Date -Format yyMMddHHMMssff), $FlagsId = 777)

$envParams = @{
	ResourceGroupName = ('BSidesTLV-' + $TeamNumber)
	ADFQDN            = 'bsidestlv.local'
	ParametersFileId  = $FlagsId
	DetailedLocalFile = $true
	SkipWebApp        = $true
	Promiscuous       = $true
	FlagPrefix        = 'BSidesTLV'
}
.\Start-LudusMagnus.ps1 @envParams 