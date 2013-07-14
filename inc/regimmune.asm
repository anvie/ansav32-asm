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


;-------------------------------------- regimmune.asm ----------------------------------------;

.data
		szUserReg           db "SOFTWARE\Microsoft\Windows NT\CurrentVersion\",0
		szRegImageFileEx	db "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ansav.exe",0
        szRegWinlogon       db "Winlogon\",0
        szRegShell          db "Shell",0
        szRegExplorer       db "Explorer.exe",0
        szRegUserInit       db "UserInit",0 
        szUserInitExe       db "userinit.exe,",0
        szRegAltShellArray  db "SYSTEM\ControlSet001\Control\SafeBoot\",0
                            db "SYSTEM\ControlSet002\Control\SafeBoot\",0
                            db "SYSTEM\CurrentControlSet\Control\SafeBoot\",0,0,0
        szRegAlternateShell db "AlternateShell",0
        szRegCmd            db "cmd.exe",0
        
        szRegSoftClass      db "Software\CLASSES\%s\shell\open\command\",0
        szRSCUnHook         db "batfile",0
                            db "comfile",0
                            db "exefile",0
                            db "piffile",0
                            db "scrfile",0
                            db "cmdfile",0
                            db 0,0

        szExeDefaultReg     db '"%1" %*',0 
        szRegFile           db "regfile",0
        szRegFileDefault    db 'regedit.exe "%1"',0
        
	HKCU equ HKEY_CURRENT_USER
	HKLM equ HKEY_LOCAL_MACHINE
	
.code

align 16

RegImmune proc uses edi esi ebx
	
    LOCAL vBuff:DWORD
    LOCAL lBuff[260]:BYTE
    LOCAL lBuff2[260]:BYTE
    LOCAL dHkey:DWORD

	; ------- seh installation ------- ;
	SehBegin 	_ri

    invoke LocalAlloc,GPTR,512
    test eax,eax
    jnz @mem_ok
    	SehPop
    	xor eax,eax
    ret
@mem_ok:
    mov vBuff,eax
	mov esi,eax

    invoke lstrcpy,esi,offset szUserReg
    invoke lstrcat,esi,offset szRegWinlogon
    
    mov 	ebx,SetRegString
    
    ;---Fix WindowsNT Winlogon---------
    mov 	edi,offset szRegShell
    scall 	ebx,HKCU,vBuff,edi,offset szRegExplorer
    scall 	ebx,HKLM,vBuff,edi,offset szRegExplorer

    mov dHkey,80000000h

@loop1:
    lea edi,lBuff
    MovZero 260
    
    inc dHkey
    
    invoke 	GetRegString,edi,dHkey,vBuff,offset szRegUserInit
    .If (byte ptr [edi])
        mov esi,edi
        
        lea edi,lBuff2
        invoke 	MyZeroMemory,edi,260

        invoke GetSystemDirectory,edi,260
        push edi
        EndString 260
        cmp byte ptr [edi-1],05ch
        je @F
        mov byte ptr [edi],05ch
      @@:
        pop edi
        
        invoke lstrcat,edi,offset szUserInitExe        
        invoke lstrcmpi,esi,edi
        test eax,eax
        je @F
        scall 	ebx,dHkey,vBuff,offset szRegUserInit,edi
      @@:
    .EndIf
    mov eax,dHkey
    cmp ax,2
    jb @loop1
        
    ;-------reg fix alternate shell----------------;
    lea edi,szRegAltShellArray   
 @loop2:
    scall 	ebx,HKLM,edi,offset szRegAlternateShell, offset szRegCmd
    NextArray @loop2

    ;---------reg fix software\CLASSES------------;
    lea edi,szRSCUnHook
 @loop5:
    xchg esi,edi
    mov edi,vBuff
    MovZero 512
    xchg esi,edi
    
    invoke wsprintf,vBuff,ADDR szRegSoftClass,edi

    scall 	ebx,HKLM,vBuff,NULL,offset szExeDefaultReg
    NextArray @loop5

    invoke wsprintf,vBuff,offset szRegSoftClass,offset szRegFile
    scall 	ebx,HKLM,vBuff,NULL,offset szRegFileDefault

	invoke 	DeleteKey,HKEY_LOCAL_MACHINE,offset szRegImageFileEx

    invoke LocalFree,vBuff
@the_end:


	; ------- seh trapper ------- ;
	SehTrap 	_ri
		ErrorDump	"RegImmune",offset RegImmune,"regimmune.asm"
	SehEnd 		_ri
	
	ret

RegImmune endp
