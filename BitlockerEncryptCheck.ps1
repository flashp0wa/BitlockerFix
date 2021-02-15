Do { 
Start-Sleep -s 10
$objBTLCKR = manage-bde -status c:

    If ($objBTLCKR -like ('*'+'Conversion Status:    Fully Encrypted'+'*')){write-host 'Drive C: is Fully Encrypted!'}
    

} 
Until($objBTLCKR -like ('*'+'Conversion Status:    Fully Encrypted'+'*'))