# Script used to export security group members to a CSV file
# by Jared Freed

param([String] $target, [String] $targetlist, [String] $output)

function GatherMemberProps($memberid)
{
    return Get-ADUser -Identity $memberid -Property * | Select-Object -Property SamAccountName, Name, Title, mail, department, Manager, physicalDeliveryOfficeName, Enabled
}
function GatherGroupMember($sg)
{
    try
    {
        foreach($member in Get-ADGroupMember -identity $sg)
        {
            Write-Progress -ID 1 -ParentID 0 "Found member: $($member.name)"
            $member = GatherMemberProps($member.SamAccountName)
            $date_modified = ScrapeObjectMetadata $sg $member.SamAccountName
            $member | Add-Member -NotePropertyName 'VDISecurityGroup' -NotePropertyValue $sg &&
            $member | Add-Member -NotePropertyName 'DateModified' -NotePropertyValue $date_modified[1] &&
            $member | Export-CSV -Path $output -Append
        }
    }
    catch{Write-Output "Unable to find group '$sg'"}
}

# Call repadmin to gather object metadata
function ScrapeObjectMetadata($sg, $user)
{
    $data = (repadmin /showobjmeta $(Get-ADDomainController).Hostname (Get-ADGroup -identity $sg).DistinguishedName) |
    Select-String -Context 0,2 "PRESENT" 
    foreach($rep in $data)
    {
        if($rep -match $user -or $rep -match $(Get-ADUser -Identity $user).Name)
        {
            $rep -match "\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"
            return $Matches[0]
        }
    }
}
function Main($target, $targetlist, $output)
{
    if(! $targetlist -and ! $output -or ! $target -and ! $output)
    {
        Write-Output "Please provide '-target <security group>' or -targetlist <path>' and '-output <path>' parameters"
        Write-Output "Example: powershell -ep bypass -f getmembers.ps1 -targetlist C:\Users\mylist.txt -output C:\Users\mycsvfile.csv"
        exit
    }

    if($targetlist)
    {
        foreach($sg in Get-Content $targetlist)
        {
            Write-Progress -ID -0 "Exporting members for group: $sg" 
            GatherGroupMember($sg)
        }
    }
    elseif($target)
    {
        Write-Progress -ID -0 "Exporting members for group: $sg" 
        GatherGroupMember($target)
    }
    
}

Main $target $targetlist $output