#requires -version 4
<#
    .SYNOPSIS
        Finds raw volumes, creates partitions.  Finds free space and allocates it to partitions.
    .DESCRIPTION
        This script is designed to find any offline disks, bring them
        online, initialize\format the partitions and assign the next available
        drive letter.

        For free space found on an existing disk, it will grow the partition
        utilizing all available free space.

    .NOTES
        Version:        1.0.1
        Author:         Dusty Lane
        Creation Date:  06/08/2020
        Purpose/Change: add some error handling and change logic.
  
#>

try {
    # Get the disks

    $Disks = Get-Disk

    foreach ($Disk in $Disks) 
    {
        # My thought process is to 
        # Bring all the drives online if they are offline....

        # Let filter through any drive that might be offline.
        if ($disk.operationalstatus -eq "Offline")
        {
            $disk | set-disk -isoffline $false 
            $disk | set-disk -isReadOnly $false
        }

        # I want to make sure that all 'raw' drives are formatted 
        # But we need to add drive letters in order....  going to 
        # convert letter to numbers and add 1, then convert back to letters.
        #
        # format any volumes that are 'raw'
        if ($disk.partitionstyle -eq 'RAW')
        {
            Initialize-Disk -Number $disk.DiskNumber -PartitionStyle GPT -PassThru -ErrorAction SilentlyContinue
            
            # need to get the drive letter that would be next in line....
            $findletter = ((get-volume | where-object {$_.driveletter -match '.'}).driveletter | Sort-Object)[-1]
            $letter = [byte]$findletter + 1
            $letter = [char]$letter
            New-Partition -DiskNumber $disk.DiskNumber -DriveLetter $letter -UseMaximumSize
            Format-Volume -DriveLetter $letter -FileSystem NTFS -NewFileSystemLabel "$($letter)_Drive" -Confirm:$false
        }
    }

    # Get volumes
    $Volumes = get-volume | where-object {$_.driveletter -match '.'} | where-object {$_.DriveType -eq 'Fixed'}

    # Get partitions on each volume
    foreach ($Volume in $Volumes)
    {
        # The intent here is to see if any of the drives have had space added them.
        # I think that to do this, we need to check the partition and compare to the volume.
        # we need to get some variables to make this happen
        $Partition = Get-Partition -DriveLetter $Volume.DriveLetter
        $disk = Get-Disk | Where-Object {$_.path -eq $partition.diskid}
        # get the maximum the size the partition can be.
        $size = (Get-PartitionSupportedSize -DiskNumber $disk.number -PartitionNumber $Partition.PartitionNumber)
        if (($Size.SizeMax - $volume.Size) -gt 102400000)
        {
            Write-output "Resizing volume $($Volume.DriveLetter)"
            Resize-Partition -DiskNumber $disk.number -PartitionNumber $Partition.PartitionNumber -Size $size.SizeMax -confirm:$false -whatif
        }
    }    
}
catch {
    $error[0]
}
