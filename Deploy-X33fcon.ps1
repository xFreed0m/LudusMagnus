param($TeamNumber = (Get-Date -Format yyMMddHHMMssff))
.\Start-LudusMagnus.ps1 -ResourceGroupName ('x33fcon-' + $TeamNumber) -ADFQDN x33fcon.local -DetailedLocalFile