;------------------------------------------------------------------------------;
;
;   ANSAV An's Antivirus
;   Copyright (C) 2007-2008 Muqorrobien Ma'rufi a.k.a 4NV|e
;
;   
;   Muqorrobien Ma'rufi a.k.a 4NV|e
;   anvie_2194 @ yahoo.com
;   http://www.ansav.com
;   PP. Miftahul Huda Blok C Siwatu Wonosobo 56352 Jawa Tengah Indonesia
;   
;
;------------------------------------------------------------------------------;


; ------- Registry.asm ------- ;
; for Registry operation stuff

.code


; ллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
SetRegString  proc uHKEY: dword, lpszKeyName: dword, lpszValueName: dword, lpszString: dword
    local Disp: dword
    local pKey: dword
    local dwSize: dword
    invoke RegCreateKeyEx, uHKEY,
        lpszKeyName, NULL, NULL, 
        REG_OPTION_NON_VOLATILE, 
        KEY_ALL_ACCESS, NULL,
        addr pKey, addr Disp
    .if eax == ERROR_SUCCESS
    

        strlen lpszString
        
        mov dwSize, eax
        invoke RegSetValueEx, pKey, lpszValueName, 
            NULL, REG_SZ, 
            lpszString, dwSize 
        push eax
        invoke RegCloseKey, pKey
        pop eax
    .endif
    ret
SetRegString endp

; ллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
GetRegString proc lpszBuffer: dword, lpHKEY: dword, lpszKeyName: dword, lpszValueName: dword
    local TType: dword
    local pKey: dword
    local dwSize: dword
    mov TType, REG_SZ
    invoke RegOpenKey, lpHKEY, lpszKeyName, addr pKey
    invoke RegQueryValueEx, pKey, lpszValueName, NULL, NULL, NULL, addr dwSize
    invoke RegCreateKeyEx, lpHKEY, lpszKeyName, NULL, NULL, REG_OPTION_NON_VOLATILE, 
        KEY_ALL_ACCESS, NULL, addr pKey, addr TType
    .if eax == ERROR_SUCCESS
        mov eax, REG_DWORD
        mov TType, eax
        inc dwSize
        invoke RegQueryValueEx, pKey, lpszValueName, 
            NULL, addr TType, 
            lpszBuffer, addr dwSize
        push eax
        invoke RegCloseKey, pKey
        pop eax
    .endif
    ret
GetRegString endp


; ллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
DeleteKeyValue proc uHKEY:DWORD, lpszKeyName:DWORD, sValueName:DWORD
    local Disp: dword
    local pKey: dword
    local dwSize: dword
    invoke RegCreateKeyEx, uHKEY,
        lpszKeyName, NULL, NULL, 
        REG_OPTION_NON_VOLATILE, 
        KEY_ALL_ACCESS, NULL,
        addr pKey, addr Disp
    .if eax == ERROR_SUCCESS
        invoke RegDeleteValue,pKey,sValueName
        push eax
        invoke RegCloseKey, pKey
        pop eax
    .endif
    ret

DeleteKeyValue endp

; ллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
SetRegDword proc uHKEY: dword, lpszKeyName: dword, lpszValueName: dword, lpdwValue: dword
    local Disp: dword
    local pKey: dword
    local dwValue: dword
    push lpdwValue
    pop dwValue
    DW_SIZE equ 4
    invoke RegCreateKeyEx, uHKEY,
        lpszKeyName, NULL, NULL, 
        REG_OPTION_NON_VOLATILE, 
        KEY_ALL_ACCESS, NULL,
        addr pKey, addr Disp
    .if eax == ERROR_SUCCESS
        invoke RegSetValueEx, pKey, lpszValueName, 
        NULL, REG_DWORD_LITTLE_ENDIAN, 
        addr dwValue, DW_SIZE
        push eax
        invoke RegCloseKey, pKey
        pop eax
    .endif
    ret
SetRegDword endp

; ллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
GetRegDword proc uHKEY: dword, lpszKeyName: dword, lpszValueName: dword, lpdwValue: dword
    local Temp: dword
    local pKey: dword
    local DWordSize: dword
    DW_SIZE EQU 4
    mov DWordSize, DW_SIZE
    invoke RegCreateKeyEx, uHKEY, 
        lpszKeyName, NULL, NULL, 
        REG_OPTION_NON_VOLATILE, 
        KEY_ALL_ACCESS, NULL,
        addr pKey, addr Temp
    .if eax == ERROR_SUCCESS
        mov eax, REG_DWORD
        mov Temp, eax
        invoke RegQueryValueEx, pKey, lpszValueName, 
            NULL, addr Temp, 
            lpdwValue, addr DWordSize 
        push eax
        invoke RegCloseKey, pKey
        pop eax
    .endif
    ret
GetRegDword endp

align 16

DeleteKey proc uHKEY:DWORD, lpszKey:DWORD
	
	invoke 	RegDeleteKey,uHKEY,lpszKey
	ret

DeleteKey endp

