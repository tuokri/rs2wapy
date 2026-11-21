# Creates disposable synthetic tracking/member/ban pagination data.
$tracking = 'O:\rs2server\ROGame\Config\ROTrackDb.ini'
$members = 'O:\rs2server\ROGame\Config\ROMemberDb.ini'
$game = 'O:\rs2server\ROGame\Config\ROGame.ini'

$trackLines = Get-Content -LiteralPath $tracking
$trackHeader=$trackLines | Where-Object { ($_ -match '^\[|^DbVersion=') }
$trackReal = $trackLines | Where-Object {
    $_ -match '^Table_' -and
    $_ -notmatch 'synthetic-tracking|synthetic-punk|xxMEMBER_DUMMY_ENTRY_DO_NOT_REMOVE'
}
$syntheticTrack = @()
for ($i = 1; $i -le 60; $i++) {
    $n = $i.ToString('D3')
    $hex = ('{0:X16}' -f (0x7000000000000000 + $i))
    $playerId = '0x' + $hex
    $a = 20000000 + $i
    $steamId = '7656119900000' + $i.ToString('D5')
    $punkId = 'synthetic-punk-' + $n
    $syntheticTrack += ('Table_Players=(PlayerID="{0}",NetId=(Uid=(A={1},B=17825793)),SteamId64="{2}",PlayerNames=("synthetic-tracking-{3}"),Created="2026/11/21 - 12:50:00",LastSeen="2026/11/21 - 12:50:00",alias=(Who=(Name=,NetId=(Uid=(A=0,B=0))),Created=,alias=),NoteIds=,PunkIds=("{4}"),NrOf=(Kicks=0,SessionBans=0,Bans=1,Connects=0),Track=False)' -f $playerId, $a, $steamId, $n, $punkId)
    $syntheticTrack += ('Table_Punks=(PunkId="{0}",PlayerID="{1}",Admin=(Name="Synthetic",NetId=(Uid=(A=0,B=0))),Created="2026/11/21 - 12:50:00",Closed=,PunkName="synthetic-tracking-{2}",Reason="Synthetic pagination ban",Expires=,Type=PunkType_Ban,Status=PunkStatus_Active,Offline=True)' -f $punkId, $playerId, $n)
}
$trackDummy = @(
    'Table_Punks=(PunkId="xxMEMBER_DUMMY_ENTRY_DO_NOT_REMOVE",PlayerID="xxMEMBER_DUMMY_ENTRY_DO_NOT_REMOVE",Admin=(Name=,NetId=(Uid=(A=0,B=0))),Created="12/14/1980 0:00:01",Closed=,PunkName="xxMEMBER_DUMMY_ENTRY_DO_NOT_REMOVE",Reason="xxMEMBER_DUMMY_ENTRY_DO_NOT_REMOVE",Expires=,Type=PunkType_None,Status=PunkStatus_None,Offline=True)',
    'Table_Players=(PlayerID="xxMEMBER_DUMMY_ENTRY_DO_NOT_REMOVE",NetId=(Uid=(A=0,B=0)),SteamId64="0x0",PlayerNames=("xxMEMBER_DUMMY_ENTRY_DO_NOT_REMOVE"),Created="12/14/1980 0:00:01",LastSeen="12/14/1980 0:00:01",alias=(Who=(Name=,NetId=(Uid=(A=0,B=0))),Created=,alias=),NoteIds=,PunkIds=("xxMEMBER_DUMMY_ENTRY_DO_NOT_REMOVE"),NrOf=(Kicks=0,SessionBans=0,Bans=0,Connects=0),Track=False)'
)
Set-Content -LiteralPath $tracking -Value (($trackHeader + $trackReal + $syntheticTrack + $trackDummy) -join "`r`n") -Encoding UTF8

$memberLines = Get-Content -LiteralPath $members
$memberHeader=$memberLines | Where-Object { ($_ -match '^\[|^DbVersion=') }
$memberReal = $memberLines | Where-Object {
    $_ -match '^Table_' -and
    $_ -notmatch 'synthetic-member|xxMEMBER_DUMMY_ENTRY_DO_NOT_REMOVE'
}
$syntheticMembers = @()
for ($i = 1; $i -le 60; $i++) {
    $n = $i.ToString('D3')
    $hex = ('{0:X16}' -f (0x7100000000000000 + $i))
    $memberId = '0x' + $hex
    $a = 30000000 + $i
    $steamId = '7656119900010' + $i.ToString('D5')
    $syntheticMembers += ('Table_Members=(MemberId="{0}",NetId=(Uid=(A={1},B=17825793)),SteamId64="{2}",MemberName="synthetic-member-{3}",alias=,AdminConfig=,Created="2026/11/21 - 12:50:00",LastSeen="2026/11/21 - 12:50:00",Expires=,Status=SubscriptionStatus_Active,Closed=)' -f $memberId, $a, $steamId, $n)
}
$memberDummy = 'Table_Members=(MemberId="xxMEMBER_DUMMY_ENTRY_DO_NOT_REMOVE",NetId=(Uid=(A=0,B=0)),SteamId64="0x0",MemberName="xxMEMBER_DUMMY_ENTRY_DO_NOT_REMOVE",alias=,AdminConfig=,Created="12/14/1980 0:00:01",LastSeen="12/14/1980 0:00:01",Expires=,Status=SubscriptionStatus_Cancelled,Closed=)'
Set-Content -LiteralPath $members -Value (($memberHeader + $memberReal + $syntheticMembers + $memberDummy) -join "`r`n") -Encoding UTF8

$gameLines = Get-Content -LiteralPath $game
$output = @()
$inEngine = $false
foreach ($line in $gameLines) {
    if ($line -match '^\[Engine.AccessControl\]') {
        $inEngine = $true
        $output += $line
        continue
    }
    if ($line -match '^BannedIDs=') {
        if ($inEngine) {
            $output += 'BannedIDs=(Uid=(A=0,B=0))'
            for ($i = 1; $i -le 60; $i++) {
                $output += ('BannedIDs=(Uid=(A={0},B=17825793))' -f (40000000 + $i))
            }
        }
        continue
    }
    if ($line -match '^\[') {
        $inEngine = $false
    }
    $output += $line
}
Set-Content -LiteralPath $game -Value ($output -join "`r`n") -Encoding UTF8
