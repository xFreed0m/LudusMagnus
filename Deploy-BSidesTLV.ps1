param($TeamNumber = (Get-Date -Format yyMMddHHMMssff))
.\Start-LudusMagnus.ps1 -ResourceGroupName ('bsidestlv-' + $TeamNumber) -ADFQDN bsidestlv.local -DetailedLocalFile -ParametersFileId 77