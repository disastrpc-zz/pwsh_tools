# Script used to export security group members to a CSV file
# by Jared Freed

param([String] $target, [String] $targetlist, [String] $output)

function GatherMemberProps($memberid)
{
    return Get-ADUser -Identity $memberid -Property * | Select-Object -Property SamAccountName, Name, Title, mail, department, Manager, physicalDeliveryOfficeName, Enabled
}
function GatherGroupMembers($sg)
{
    [System.Collections.ArrayList] $member_list = @()
    try
    {
        foreach($member in Get-ADGroupMember -identity $sg)
        {
            Write-Progress -ID 1 -ParentID 0 "Found member: $($member.name)"
            $member = GatherMemberProps($member.SamAccountName)
            $member | Add-Member -NotePropertyName 'VDISecurityGroup' -NotePropertyValue $sg && $member | Export-CSV -Path $output -Append
        }
    }
    catch{Write-Output "Unable to find group '$sg'"}
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
            GatherGroupMembers($sg)
        }
    }
    elseif($target)
    {
        Write-Progress -ID -0 "Exporting members for group: $target" 
        GatherGroupMembers($target)
    }
    
}

Main $target $targetlist $output
