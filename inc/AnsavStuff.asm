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

; ------- AnsavStuff.asm ------- ;
crcCalc		PROTO :dword, :dword

.data
	szAnsavStuffasm db "AnsavStuff.asm",0
	szUtilsBuff db 1024*2 dup(0)
	szKillfnrF db 'This file : "%s".',13,10
			   db 'Failed to clean, may be used by another process.',13,10
			   db 'ANSAV can delete it after system reboot.',13,10
			   db 'Click "Yes" if you want ANSAV to delete this object after system reboot',0  
.code

align 16

; ------- LOCAL MACRO ------- ;
StatusIdleWait MACRO
	invoke 	SetMainTxtStatus2,ADDR szStatusIdle,ADDR szWaitForCmd
endm

StatusIdle MACRO
	invoke 	SetMainTxtStatus2,ADDR szStatusIdle,0
endm

StatusBuffering MACRO
	invoke 	SetMainTxtStatus2,ADDR szStatusBuffering,0
endm

StatusChecking MACRO
	invoke 	SetMainTxtStatus2,ADDR szStatusChecking,0
endm

StatusCleaning MACRO
	invoke 	SetMainTxtStatus2,ADDR szStatusCleaning,0
endm

SetStatus MACRO arg
	LOCAL 	nustr
	.data
		nustr db arg,0
	.code
	invoke 	SetMainTxtStatus2,offset nustr,0
endm

align 16

; ------- Get all needed path like SysDir, WinDir etc... ------- ;
GetPathPath proc uses edi esi ebx
	LOCAL 	lBuff[MAX_PATH+1]:BYTE

	; ------- seh installation ------- ;
	SehBegin	__gpp

	invoke 	MyZeroMemory,ADDR lBuff,MAX_PATH
	
	mov 	esi,lstrcpy
	
	; ------- Get MyPath ------- ;
	invoke 	GetModuleFileName,0,ADDR szMyPath,MAX_PATH
	; ------- Get Current dir ------- ;
	scall 	esi,offset szMyDir,offset szMyPath
	invoke 	OnlyPathDir,ADDR szMyDir
	invoke 	SetCurrentDirectory,offset szMyDir

	; ------- Get Quarantine Dir ------- ;
	scall 	esi,offset szQuarantineDir,offset szMyDir
	invoke 	TruePath,ADDR szQuarantineDir
	invoke 	lstrcat,offset szQuarantineDir,offset szQuarDirName

	; ------- Get WinDir ------- ;
	invoke 	GetWindowsDirectory,ADDR szWinDir,MAX_PATH 

	; ------- Get System Dir ------- ;
	invoke 	GetSystemDirectory,ADDR szSysDir,MAX_PATH
	
	; ------- Get temp dir ------- ;
	invoke 	GetTempPath,MAX_PATH,ADDR szTempDir

	; ------- ansav temp work dir ------- ;
	invoke 	lstrcpy,offset szAnsavTempWorkDir,offset szTempDir
	invoke 	TruePath,offset szAnsavTempWorkDir

	mov 	ebx,lstrcat

	scall 	ebx,offset szAnsavTempWorkDir,reparg("ansav.tmp")

	; ------- get result.log file path based temp dir ------- ;
	scall 	esi,offset szTempFilePath,offset szTempDir
	invoke 	TruePath,ADDR szTempFilePath
	scall 	ebx,offset szTempFilePath,offset szTempResultFileName 

	; ------- get current ansav ini path ------- ;
	scall 	esi,offset szAnsavIniPath,offset szMyDir
	invoke 	TruePath,ADDR szAnsavIniPath
	scall 	ebx,offset szAnsavIniPath,offset szAnsavIni
	
	scall 	esi,offset szPluginsPath,offset szMyDir
	invoke 	TruePath,ADDR szPluginsPath
	scall 	ebx,offset szPluginsPath,reparg("Plugins")

	; ------- Get module an32hk.dll ------- ;
	; to control service
	
	lea 	edi,szAnhookerPath
	scall 	esi,edi,offset szWinDir
	invoke 	TruePath,edi
	scall 	ebx,edi,offset szAnhookerDll

	invoke 	lstrcpy,offset szanPdetectorPath,offset szMyDir
	invoke 	TruePath,offset szanPdetectorPath
	invoke 	lstrcat,offset szanPdetectorPath,offset szanPdetectordll

	; ------- trust zone ------- ;
	invoke 	lstrcpyn,offset szTrustDataPath,offset szMyDir,MAX_PATH
	invoke 	TruePath,offset szTrustDataPath
	invoke 	lstrcat,offset szTrustDataPath,offset szTrustDataFile


	; ------- seh trap ------- ;
	SehTrap 	__gpp
		ErrorDump	"GetPathPath",offset GetPathPath,offset szAnsavStuffasm
	SehEnd		__gpp

	ret
GetPathPath endp

align 16

; ------- For check that extention can run? ------- ;
IsRunnable proc uses esi lpszExt:DWORD
    LOCAL dBuffer,dBuffer2:DWORD
    LOCAL retv:DWORD

	; ------- seh installation ------- ;
	SehBegin	__ir

    mov 	retv,0

	mov 	esi,lstrcmpi
	scall 	esi,lpszExt,reparg(".lnk") ; exclude shortcut
	jnz 	@F
		SehPop
		return_0
	@@:
	scall 	esi,lpszExt,reparg(".url") ; exclude shortcut
	jnz 	@F
		SehPop
		return_0
	@@:

	mov 	esi,LocalAlloc
    scall 	esi,LPTR,260
    mov 	dBuffer,eax
    scall 	esi,LPTR,260
    mov 	dBuffer2,eax

	.if 	!dBuffer || !dBuffer2
		SehPop
		return_0
	.endif
	
	mov 	esi,lstrcmpi
	
    invoke GetRegString,dBuffer,HKEY_CLASSES_ROOT,lpszExt,NULL
    .if !eax
        scall 	esi,dBuffer,offset szExeDefault
        jne @F
        mov retv,1
        jmp @lend
     @@:
        invoke wsprintf,dBuffer2,offset szRegExt,dBuffer
        invoke GetRegString,dBuffer,HKEY_CLASSES_ROOT,dBuffer2,NULL
        .if !eax
            scall 	esi,dBuffer,offset szExeDefault
            jne @lend
            mov retv,1
        .endif
    .elseif eax==2
        invoke wsprintf,dBuffer2,offset szRegExt,lpszExt
        invoke GetRegString,dBuffer,HKEY_CLASSES_ROOT,dBuffer2,NULL
        .if !eax
            scall 	esi,dBuffer,offset szExeDefault
            jne @F
            mov retv,1
         @@:
        .endif
    .endif
@lend:
	
	mov 	esi,LocalFree
    scall 	esi,dBuffer2
    scall 	esi,dBuffer
    
    ; ------- seh trap ------- ;
    SehTrap 	__ir
IFNDEF 	SERVICE
    	ErrorDump	"IsRunnable",offset IsRunnable,offset szAnsavStuffasm
ENDIF
    SehEnd 		__ir
    
    mov eax,retv
    ret
IsRunnable endp

align 16

CheckAndShutdown proc
	
	call 	IsNT
	.if 	eax
		call 	SetShutdownTokenPrivilege
	.endif
	.if 	ShutdownAfterScan
		invoke	ExitWindowsEx,EWX_POWEROFF OR EWX_SHUTDOWN or EWX_FORCE,0
	.endif
	ret

CheckAndShutdown endp

align 16

DoReboot proc
	
	invoke 	IsNT
	.if 	eax
		call 	SetShutdownTokenPrivilege
	.endif
	invoke	ExitWindowsEx,EWX_REBOOT or EWX_FORCE,0
	ret

DoReboot endp

align 16

IsSuspName proc uses esi lpName:DWORD; ------- old ANSAV compatibility ------- ;

	mov 	esi,lpName
	lodsd
	cmp 	eax,'psuS'
	jne 	@F
		align 4
		ret
	@@:
	cmp 	eax,'PSUS'
	jne 	@F
		align 4
		ret
	@@:
	cmp 	eax,'/HPS'
	jne 	@F
		align 4
		ret
	@@:
	xor 	eax,eax
	ret

IsSuspName endp

align 16

GetAllVdbCount proc uses esi edi

	LOCAL 	exvdb,count:DWORD

	; ------- seh installation ------- ;
	SehBegin	 __gavc

	mov 	count,0
	mov 	exvdb,0
	
	; ------- SV ------- ;
	lea 	esi,AnsavVDBv2
	assume 	esi:ptr SVDBv2
	@lp:
		
		add 	count,1
		add 	esi,sizeof SVDBv2
		lea 	edx,[esi].szThreatName
		invoke 	IsSuspName,edx
		test 	eax,eax
		jz		@F
			dec 	count
		@@:
		
	cmp 	byte ptr [esi],0
	jne 	@lp
	assume 	esi:nothing
	
	
	; ------- check exvdb ------- ;
	.if 	ExternalVdb && ExternalVdbSize && !exvdb
		mov 	esi,ExternalVdb
		add 	esi,sizeof EXVDBINFO
		mov 	exvdb,1
		jmp 	@lp
	.endif
	
	; ------- seh trap ------- ;
	SehTrap		__gavc
		ErrorDump	"GetAllVdbCount",offset GetAllVdbCount,offset szAnsavStuffasm
	SehEnd 		__gavc
	
	
	mov 	eax,count
	ret

GetAllVdbCount endp

align 16

IsRootZip proc uses edi esi lpPath:DWORD
	LOCAL 	retv:DWORD
	LOCAL 	lBuff[4]:BYTE
	LOCAL 	lbrw:DWORD
	
	mov 	retv,0
	
	invoke 	CreateFile,lpPath, \ 
			GENERIC_READ, \ 
			FILE_SHARE_READ,0, \
			OPEN_EXISTING, \
			FILE_ATTRIBUTE_NORMAL,0
	.if 	eax!=-1
		mov 	esi,eax
		invoke 	GetFileSize,esi,0
		.if 	eax > 2
			lea 	edi,lBuff
			invoke 	ReadFile,esi,edi,2,ADDR lbrw,0
			cmp 	word ptr [edi],'KP'
			jne		@F
				mov 	retv,1
			@@:
		.endif
		invoke 	CloseHandle,esi
	.endif
	mov 	eax,retv
	ret

IsRootZip endp

align 16

LvInsertTFIItem	proc uses ebx esi edi lpTFI:DWORD

	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	LOCAL 	lvi:LV_ITEM
	LOCAL 	rz:DWORD
	
	invoke 	MyZeroMemory,ADDR lvi,sizeof LV_ITEM

	mov 	rz,0

	mov 	esi,lpTFI
	assume 	esi:ptr THREATFULLINFO
	
	; ------- check for existing one first ------- ;
	lea 	ebx,[esi].szFilePath
	invoke 	IsObjectExistsInList?,ebx
	test 	eax,eax
	jz 		@F
		ret
	@@:
	
	.if 	ArcReady
		
		invoke 	IsRootZip,ebx
		test 	eax,eax
		jz 		@F
			mov 	rz,1
			mov 	eax,reparg("Archive contain threat(s)")
			mov 	[esi].uVirusInfo.Description,eax
			
			
			lea 	eax,[esi].szThreatName
			invoke 	wsprintf,eax,offset szThreatInsideF,NumThreatInsideArc
			
		@@:
	.endif
	
	mov 	edi,SendMessage
	
	mov 	lvi.imask,LVIF_TEXT
	mov 	lvi.iItem,0
	lea 	eax,lBuff
	mov 	lvi.pszText,eax
	mov 	lvi.cchTextMax,MAX_PATH
	lea 	eax,lvi
	scall 	edi,hMainList,LVM_GETITEM,0,eax
	
	mov 	lvi.imask,LVIF_TEXT OR LVIF_IMAGE
	lea 	eax,[esi].szThreatName
	mov 	[lvi.pszText],eax
	
	.if 	rz
		mov 	eax,4
	.else
		.if 	[esi].uVirusInfo.Risk
			xor 	eax,eax
		.else
			mov 	eax,1
		.endif
	.endif

	mov 	[lvi.iImage],eax
	lea 	eax,lvi
	scall 	edi,hMainList,LVM_INSERTITEM,0,eax
	
	mov 	lvi.imask,LVIF_TEXT
	inc 	lvi.iSubItem
	lea 	eax,[esi].szFilePath
	mov 	lvi.pszText,eax
	mov 	lvi.iImage,0
	lea 	eax,lvi
	scall 	edi,hMainList,LVM_SETITEM,0,eax
	
	invoke 	MyZeroMemory,ADDR lBuff,MAX_PATH	; <-- FILE SIZE ;
	invoke 	wsprintf,ADDR lBuff,ADDR szdTosF,[esi].fSize
	lea 	eax,lBuff
	
	invoke 	FormatKB,eax
	mov 	lvi.pszText,eax
	inc 	lvi.iSubItem
	lea 	eax,lvi
	scall 	edi,hMainList,LVM_SETITEM,0,eax	; <-- FILE SIZE ;
	
	.if 	rz
		lea 	eax,szStrip
	.else
		lea 	eax,[esi].szThreatName
		push 	eax
		call 	IsSuspectedObject	; <-- unknown risk for heur detection ;
		test 	eax,eax
		jnz 	@unk
		movzx 	edx,[esi].uVirusInfo.Risk
		.if 		dx == VIRI_RISK_VERYLOW
			lea 	eax,szRiskVeryLow
		.elseif 	dx == VIRI_RISK_LOW
			lea 	eax,szRiskLow
		.elseif 	dx == VIRI_RISK_MEDIUM
			lea 	eax,szRiskMedium
		.elseif 	dx == VIRI_RISK_HIGH
			lea 	eax,szRiskHigh
		.elseif 	dx == VIRI_RISK_VERYHIGH
			lea 	eax,szRiskVeryHigh
		.elseif 	dx == VIRI_RISK_DANGEROUS
			lea 	eax,szRiskDanger
		.else
		@unk:
			lea 	eax,szUnknown
		.endif
	.endif

	lea 	ebx,lvi
	mov 	lvi.pszText,eax
	inc 	lvi.iSubItem
	scall 	edi,hMainList,LVM_SETITEM,0,ebx
	
	.if 	MemCheck
		lea 	eax,szDetectedInMem
		mov 	lvi.pszText,eax
		inc 	[lvi.iSubItem]
		scall 	edi,hMainList,LVM_SETITEM,0,ebx
	.else
		; ------- check for description ------- ;
		.if 	[esi].uVirusInfo.Description
			m2m 	[lvi.pszText],[esi].uVirusInfo.Description
			inc 	[lvi.iSubItem]
			scall 	edi,hMainList,LVM_SETITEM,0,ebx
		.elseif 	[esi].lpszInfo
			m2m 	[lvi.pszText],[esi].lpszInfo
			inc 	[lvi.iSubItem]
			scall 	edi,hMainList,LVM_SETITEM,0,ebx
		.endif
	.endif
	assume 	esi:nothing
	
	mov 	esi,SendMessage
	mov 	ebx,hMainList
	mov 	edi,LVM_SETCOLUMNWIDTH
	push 	ebp
	mov 	ebp,LVSCW_AUTOSIZE_USEHEADER
	
	scall 	esi,ebx,edi,0,ebp
	scall 	esi,ebx,edi,2,ebp
	scall 	esi,ebx,edi,3,ebp
	scall 	esi,ebx,edi,4,ebp
	
	pop 	ebp
@endl:
	ret
LvInsertTFIItem endp

align 16

; ------- break ------- ;
GetAllFilesCountFromThisPath proc uses edi esi ebx lpszPath:DWORD
	
    LOCAL   WFD:WIN32_FIND_DATA
    LOCAL   fPath[260]:BYTE
    LOCAL   fPath2[260]:BYTE
    LOCAL   hFind:DWORD

	cmp 	StopScan,1
	je 		@the_end

    lea 	edi,fPath
    MovZero	MAX_PATH
    
    invoke  lstrcpy,edi,lpszPath

	align 4

    .while 	byte ptr [edi]
    	add 	edi,1
    .endw

    cmp 	byte ptr [edi-1],'\'
    je  	@F
    mov 	word ptr [edi],'*\'
    jmp 	@nx
@@:
	mov 	byte ptr [edi],'*'
@nx:

    lea edi,[WFD.cFileName]
    MovZero	MAX_PATH

	align 4

    invoke  FindFirstFile,ADDR fPath,ADDR WFD

    push eax
    
    	mov hFind,eax
    	
    pop ebx

    add eax,1
    test eax,eax
    .if zero?
    	mov 	edi,AppendLogConsole ; 14907
    	
    	scall 	edi,reparg("Cannot open this path :")
    	scall 	edi,lpszPath
    	jmp @the_end
    .endif
    
    align 4

    .WHILE ebx > 0
        lea esi,[WFD.cFileName]
        lodsw

        .IF AX!=02e2eh && AX!=0002eh
            mov 	eax,DWORD PTR WFD[0]
            
            .If ax & FILE_ATTRIBUTE_DIRECTORY
            
            	align 4
            
                sub esi,2
                	push esi
                lea edi,fPath2
                MovZero	MAX_PATH

                lea eax,fPath
                invoke lstrcpy,edi,eax

                	push edi
                mov al,'*'
                scasb 
                jnz $-1
                mov byte ptr [edi-1],0
                	pop edi
                	pop esi
                invoke lstrcat,edi,esi
                
                align 4

                push 	edi
                call 	GetAllFilesCountFromThisPath
                
            .Else
                add 	AllFilesCount,1
            .EndIf
        .EndIf
        lea edi,WFD.cFileName
        MovZero	MAX_PATH

		align 4

        invoke FindNextFile,hFind,ADDR WFD
        mov ebx,eax
    .ENDW
    invoke FindClose,hFind

@the_end:
    ret

GetAllFilesCountFromThisPath endp

align 16

.data?
	ThreatPathDetected dd ?
.code

align 16

CheckThisPath proc uses edi esi ebx lpszPath:DWORD
    LOCAL   WFD:WIN32_FIND_DATA
    LOCAL   fPath[260]:BYTE
    LOCAL   fPath2[260]:BYTE
    LOCAL   hFind:DWORD

	cmp 	StopScan,1
	je 		@the_end	

    lea edi,fPath
    MovZero 260 	; <-- need for speed ;
    
    invoke lstrcpy,edi,lpszPath

	align 4

    ; ------- optimized ------- ;
    .while 	byte ptr [edi]
    	add 	edi,1
    .endw
    ; -------------- ;

    cmp 	byte ptr [edi-1],'\'
    je  	@F
    mov 	word ptr [edi],'*\'
    jmp 	@nx
@@:
	mov 	byte ptr [edi],'*'
@nx:

	align 4

    lea edi,[WFD.cFileName]
    MovZero 260 	; <-- need for speed ;

    invoke FindFirstFile,ADDR fPath,ADDR WFD

    push eax
    	mov hFind,eax
    pop ebx

    add eax,1	; <-- optimized ;
    test eax,eax
    jz @the_end
    
	align 4
	
    .WHILE ebx > 0
        lea esi,WFD.cFileName
        lodsw

        .IF AX!=02e2eh && AX!=0002eh
            mov 	eax,dword ptr WFD[0]
            
            .If ax & FILE_ATTRIBUTE_DIRECTORY
            
            	align 4
            	
                sub esi,2
                push esi
                lea edi,fPath2
                MovZero 	260	; <-- need for speed ;

                lea eax,fPath
                invoke lstrcpy,edi,eax

                push edi
                mov al,'*'
                scasb 
                jnz $-1
                mov byte ptr [edi-1],0
                pop edi
                pop esi
                invoke lstrcat,edi,esi
                
                align 4
                
                invoke CheckThisPath,edi
                
            .Else
            
				cmp 	StopScan,1
				je 		@fclose	
            	align 4
            	
                sub esi,2
                
                lea edi,fPath2
                MovZero 	260	; <-- need for speed ;
                
                ; ------- optimized ------- ;
                push edi
                push esi
                
                lea esi,fPath
             @@:
                mov al,byte ptr [esi]
                mov byte ptr [edi],al	; <-- need for speed ;
                add edi,1
                add esi,1

                test al,al
             jne @B
                sub edi,3
                mov word ptr [edi],0005ch

                pop esi
                pop edi
                ; -------------- ;

                invoke lstrcat,edi,esi
                
                align 4
                
                invoke 	CheckThisFile,edi,ADDR gTFI ;,0
                .if 	eax
                	mov 	ThreatPathDetected,eax
                	invoke 	LvInsertTFIItem,ADDR gTFI
                	.if 	ArcReady
                		invoke 	IsRootZip,edi
                		.if 	!eax
                			inc 	DetectedThreatsCnt
                		.endif
                		.if 	InsideZip
                			inc 	NumThreatInsideArc
                		.endif
                	.else
                		inc 	DetectedThreatsCnt
                	.endif
                	invoke 	wsprintf,ADDR szDetectedThreatCntBuff,ADDR szdTosF,DetectedThreatsCnt
                	invoke 	SetWindowText,hTxtDetectedThreats,ADDR szDetectedThreatCntBuff
                .endif
                
            .EndIf
        .EndIf
        lea edi,WFD.cFileName
        MovZero 260	; <-- optimized ;

		align 4
		
        invoke FindNextFile,hFind,ADDR WFD
        mov ebx,eax
    .ENDW
@fclose:
    invoke FindClose,hFind

@the_end:
    ret

CheckThisPath endp

include 	inc/status.asm
align 16

InitScan proc

	call 	HideAllStatus

	xor 	eax,eax

	mov 	AllFilesCount,eax
	mov 	DetectedThreatsCnt,eax
	mov 	StopScan,eax
	mov 	MainPBPos,eax
	mov 	InsideZip,eax
	mov 	FileScanAborted,eax
	
	; ------- time ------- ;
	invoke 	GetLocalTime,ADDR TimeBeginScan
	
	push 	esi
	mov 	esi,MyZeroMemory
	
	lea 	eax,TimeEndScan
	scall 	esi,eax,sizeof SYSTEMTIME
	lea 	eax,TimeTakeA
	scall 	esi,eax,sizeof SYSTEMTIME
	
	pop 	esi
	
	xor 	eax,eax
	mov 	DontShort,eax
	inc 	eax
	mov 	InScanning,eax
	
	.if		!MemCheck
		.if 	ArcReady
			; ------- clean temp ------- ;
			invoke 	GenocideThisPath,offset szAnsavTempWorkDir
		.endif
	.endif
	
	lea 	eax,tmrCapPercent
	invoke 	SetTimer,hMainWnd,1234,500,eax
	
	ret

InitScan endp

align 16

; ------- for scan all of existing removable media ------- ;
ScanAllHardisk proc uses esi

	LOCAL 	pDrives:DWORD
	
	; ------- seh installation ------- ;
	SehBegin	__sah
	
	
	mov 	esi,AppendLogConsole
	
	invoke 	SetCtrlDS,STATE_DISABLE
	invoke 	SetActionTbState,STATE_DISABLE
	
	invoke 	AppendLogConsole,ADDR szAllocMemForDrv
	valloc 	1024+1
	.if 	eax
		mov 	pDrives,eax
		
		scall 	esi,offset szSuccess
		scall 	esi,reparg("Get all available drives...")
		
		
		invoke 	GetAllDrives,pDrives,1024
		.if 	eax
			
			scall 	esi,offset szInitSLS
			
			; ------- Populate progbar ------- ;
			mov 	edi,pDrives
			call 	InitScan
			call 	InitLastScannedBuffer
			
			call 	SetAllMainCtrlState
			
			scall 	esi,offset szBuffering
			StatusBuffering 	; <-- Set status ;
			
			@lp:
				invoke 	GetDriveType,edi
				.if 	eax == DRIVE_FIXED
					mov 	InScanning,1
					push 	edi
					call 	GetAllFilesCountFromThisPath
				.endif
			NextArray 	@lp
			
			invoke 	SendMessage,hMainProgBar,PBM_SETRANGE32,0,AllFilesCount
			
			; ------- Processing ------- ;
			; now let's checking
			StatusChecking 		; <-- Set status ;
			mov 	edi,pDrives
			
			@lp2:
				invoke 	GetDriveType,edi
				.if 	eax == DRIVE_FIXED
				
					scall 	esi,reparg("Checking for :")
					scall 	esi,edi
					
					invoke 	CheckThisPath,edi
					.if 	!StopScan
						invoke 	InsertLastScannedPathBuffer,edi
					.endif
				.endif
			NextArray	@lp2
			
			
			scall 	esi,offset szFlushBuffer
			; ------- Save result ------- ;
			invoke 	SaveResult,ADDR szAllHardisk
			
			push 	esi
			
			mov 	esi,SendMessage
			
			.if 	StopScan
				invoke 	SetDlgItemText,hMainWnd,IDC_EDIT_PATH,ADDR szCheckStoped
				scall 	esi,hMainProgBar,PBM_SETPOS,0,0
			.else
				invoke 	SetDlgItemText,hMainWnd,IDC_EDIT_PATH,ADDR szCheckComplete
				scall 	esi,hMainProgBar,PBM_SETPOS,AllFilesCount,0
			.endif
			
			pop 	esi
			
			mov 	StopScan,1
			StatusIdleWait 		; <-- Set status ;
			
			.if 	DetectedThreatsCnt
				invoke 	SetMainTxtStatus,STATUS_DETECTED
				invoke 	SetActionTbState,STATE_ENABLE
				scall 	esi,offset  szCheckCmpltDC
			.else
				invoke 	SetMainTxtStatus,STATUS_CLEAN
				invoke 	SetActionTbState,STATE_DISABLE
				scall 	esi,offset szCheckCmpltNDC
			.endif
			
		.else
			ViewError	hMainWnd,"ERROR: Cannot capture all drives"
		.endif
		
		scall 	esi,offset szFreeMem
		vfree 	pDrives
	.else
		scall 	esi,offset szFailed
		ViewError 	hMainWnd,"ERROR: Cannot allocate memory for capturing all drives"
	.endif
	
	; ------- seh trap for ScanAllHardisk ------- ;
	SehTrap 	__sah
		ErrorDump	"ScanAllHardisk",offset ScanAllHardisk,offset szAnsavStuffasm
	SehEnd		__sah
	
	scall 	esi,offset szScanLogReady
	invoke 	SetCtrlDS,STATE_ENABLE
	ret

ScanAllHardisk endp

align 16

StartScanAllHardisk proc
	
	LOCAL 	ThID:DWORD
	invoke 	SendMessage,hMainList,LVM_DELETEALLITEMS,0,0
	invoke 	CreateThread,0,0,ADDR ScanAllHardisk,0,0,ADDR ThID
	invoke 	CloseHandle,eax
	ret

StartScanAllHardisk endp

align 16

; ------- for scan all of existing removable media ------- ;	; <-- thread ;
ScanAllRemovableMedia proc uses edi esi lParam:DWORD

	LOCAL 	pDrives:DWORD

	; ------- seh installation ------- ;
	SehBegin 	__sarm

	invoke 	SetCtrlDS,STATE_DISABLE
	invoke 	SetActionTbState,STATE_DISABLE
	
	mov 	esi,AppendLogConsole
	
	scall 	esi,offset szAllocMemForDrv
	valloc 	1024+1
	.if 	eax
		mov 	pDrives,eax
		
		scall 	esi,offset szSuccess
		scall 	esi,reparg("Get all available drives...")
		
		invoke 	GetAllDrives,pDrives,1024
		.if 	eax
			
			scall 	esi,offset szSuccess
			scall 	esi,offset szInitSLS
			
			; ------- Populate progbar ------- ;
			mov 	edi,pDrives
			call 	InitScan
			
			scall 	esi,offset szBuffering
			
			; ------- prepare buffer for last scanned path ------- ;
			call 	InitLastScannedBuffer
			
			call 	SetAllMainCtrlState
			StatusBuffering 	; <-- Set status ;
			
			@lp:
				invoke 	GetDriveType,edi
				.if 	eax == DRIVE_REMOVABLE
					invoke 	lstrcmpi,edi,reparg("A:\")
					je 		@exclude
					invoke 	lstrcmpi,edi,reparg("B:\")
					je 		@exclude
					mov 	InScanning,1
					
					push 	edi
					call 	GetAllFilesCountFromThisPath
					@exclude:
				.endif
			NextArray 	@lp
			
			invoke 	SendMessage,hMainProgBar,PBM_SETRANGE32,0,AllFilesCount
			
			; ------- Processing ------- ;
			; now let's checking
			StatusChecking 		; <-- Set status ;
			mov 	edi,pDrives
			@lp2:
				invoke 	GetDriveType,edi
				.if 	eax == DRIVE_REMOVABLE
				
					scall 	esi,reparg("Checking for :")
					scall 	esi,edi
					
					invoke 	CheckThisPath,edi
					.if 	!StopScan
						invoke 	InsertLastScannedPathBuffer,edi
					.endif
				.endif
			NextArray	@lp2
			
			scall 	esi,offset szFlushBuffer
			
			; ------- Save result ------- ;
			invoke 	SaveResult,ADDR szAllRemovableMedia
			
			.if 	StopScan
				invoke 	SetDlgItemText,hMainWnd,IDC_EDIT_PATH,ADDR szCheckStoped
				invoke 	SendMessage,hMainProgBar,PBM_SETPOS,0,0
			.else
				invoke 	SetDlgItemText,hMainWnd,IDC_EDIT_PATH,ADDR szCheckComplete
				invoke 	SendMessage,hMainProgBar,PBM_SETPOS,AllFilesCount,0
			.endif
			mov 	StopScan,1
			StatusIdleWait 		; <-- Set status ;
			
			.if 	DetectedThreatsCnt
				invoke 	SetMainTxtStatus,STATUS_DETECTED
				invoke 	SetActionTbState,STATE_ENABLE
				scall 	esi,offset szCheckCmpltDC
			.else
				invoke 	SetMainTxtStatus,STATUS_CLEAN
				invoke 	SetActionTbState,STATE_DISABLE
				scall 	esi,offset szCheckCmpltNDC
			.endif
			
		.else
			scall 	esi,offset szFailed
			ViewError	hMainWnd,"ERROR: Cannot capture all drives"
		.endif
		
		scall 	esi,offset szFreeMem
		vfree 	pDrives
	.else
		scall 	esi,offset szFailed
		ViewError 	hMainWnd,"ERROR: Cannot allocate memory for capturing all drives"
	.endif
	
	scall 	esi,offset szScanLogReady
	invoke 	SetCtrlDS,STATE_ENABLE
	
	
	SehTrap 	__sarm
		ErrorDump 	"ScanAllRemovableMedia",offset ScanAllRemovableMedia,offset szAnsavStuffasm
	SehEnd 		__sarm
	
	ret

ScanAllRemovableMedia endp

align 16

StartScanAllRemovableMedia proc
	
	LOCAL 	ThID:DWORD
	invoke 	SendMessage,hMainList,LVM_DELETEALLITEMS,0,0
	invoke 	CreateThread,0,0,ADDR ScanAllRemovableMedia,0,0,ADDR ThID
	invoke 	CloseHandle,eax
	ret

StartScanAllRemovableMedia endp


align 16

IsSuspectedObject proc uses edi esi lpszObject:DWORD
	
	mov edi,lpszObject
	mov ecx,30
	mov al,'/'
	repne scasb
	jecxz @endl
	dec edi
	mov byte ptr [edi],0
	mov esi,lpszObject
	
	invoke lstrcmpi,esi,offset reparg("suspected")
	.if 	eax
		invoke lstrcmpi,esi,offset reparg("harmfull")
		test 	eax,eax
		jz 		@rev
			xor 	eax,eax
	.else
@rev:
		RevEax
	.endif
	mov byte ptr [edi],'/'
	ret
@endl:
	xor eax,eax
	ret

IsSuspectedObject endp

szKillScheduled db "Action scheduled on next boot.",0

align 16

IsAlreadyScheduled?  proc uses edi esi index:DWORD
	
	LOCAL 	buff[MAX_PATH+1]:BYTE
	LOCAL 	lvi:LV_ITEM
	
	lea 	esi,lvi
	invoke 	MyZeroMemory,esi,sizeof LV_ITEM
	lea 	edi,buff
	invoke 	MyZeroMemory,edi,MAX_PATH
	
	assume 	esi:ptr LV_ITEM
	
	mov	[esi].imask,LVIF_TEXT
	mov2 [esi].iItem,index
	mov [esi].iSubItem,4
	mov [esi].pszText,edi
	mov [esi].cchTextMax,MAX_PATH
	
	invoke 	SendMessage,hMainList,LVM_GETITEM,0,esi
	.if 	byte ptr [edi]
		invoke 	lstrcmp,edi,offset szKillScheduled
	.endif
	assume 	esi:nothing
	
	
	RevEax
	
	ret

IsAlreadyScheduled? endp


align 16

szCannotCleanThis db "Cannot clean this object.",0
szCln	db "Cleaning...",0
szDel	db "Deleting...",0
	
; ------- clean all detected threats ------- ;
; need optimization
CleanNow proc uses edi ebx esi lParam:DWORD
	LOCAL 	ItemCount,ItemIndex:DWORD
	LOCAL 	lvi:LV_ITEM
	LOCAL 	FilePath[MAX_PATH+1]:BYTE
	LOCAL 	szthName[30]:BYTE
	LOCAL 	pBuff:DWORD
	LOCAL 	wpc:WINDOWPLACEMENT
	
	invoke 	MyZeroMemory,ADDR lvi,sizeof LV_ITEM
	invoke 	MyZeroMemory,ADDR szthName,30
	
	xor 	eax,eax
	mov 	pBuff,eax
	
	valloc 	MAX_PATH*2+1
	mov 	pBuff,eax

	mov 	InAction,1

	invoke 	SetCtrlDS,STATE_DISABLE
	invoke 	SetActionTbState,STATE_DISABLE
	
	invoke 	EnableWindow,hMainList,FALSE
	
	.if 	ForFix
		lea 	eax,szCln
	.else
		lea 	eax,szDel
	.endif
	invoke 	SetMainTxtStatus2,eax,0

	mov 	esi,SendMessage
	
	scall 	esi,hMainList,LVM_GETITEMCOUNT,0,0
	.if 	eax
		mov 	ItemCount,eax
		mov 	ItemIndex,eax
		@lp:
			dec 	ItemIndex
			
			cmp 	StopClean,1
			je 		@endl
			
			invoke 	MyZeroMemory,ADDR FilePath,MAX_PATH
			
			align 4
			
			.if 	[lParam]==1
				scall 	esi,hMainList, LVM_GETITEMSTATE,ItemIndex,LVNI_SELECTED
				cmp 	eax,LVNI_SELECTED
				jne 	@nx	; <-- only for selected object ;
			.endif
			
			mov 	[lvi.imask],LVIF_TEXT
			m2m 	[lvi.iItem],ItemIndex
			mov		[lvi.iSubItem],1
			lea 	eax,FilePath
			mov 	[lvi.pszText],eax
			mov 	[lvi.cchTextMax],MAX_PATH
			lea 	eax,lvi
			scall 	esi,hMainList,LVM_GETITEM,0,eax	; <-- get path address ;
			lea 	eax,szthName
			mov 	[lvi.pszText],eax
			mov 	[lvi.iSubItem],0
			lea 	eax,lvi
			scall 	esi,hMainList,LVM_GETITEM,0,eax	; <-- get threat name ;
			
			lea 	edi,FilePath
			cmp 	byte ptr [edi],0
			je 		@nx
			
			align 4
			mov 	ebx,AppendLogConsole
			
			scall 	ebx,reparg("Try to clean this object :")
			scall 	ebx,edi
			
			invoke 	IsObjectInsideArc?,edi
			.if 	!eax
				invoke 	FileExist,edi
				.if 	!eax
					scall 	ebx,offset szFileDoesnEx
					xor 	eax,eax
					inc 	eax
					jmp 	@okay_okay
				.endif
				invoke 	SetFileAttributes,edi,FILE_ATTRIBUTE_NORMAL
			.else
				push 	esi
				push 	edi
				
				cld
				invoke 	lstrlen,edi
				mov 	ecx,eax
				mov 	al,':'
				repnz 	scasb
				repnz 	scasb
				dec 	edi
				mov 	esi,edi
				mov 	byte ptr [edi],0
				pop 	edi
				
				invoke 	SetFileAttributes,edi,FILE_ATTRIBUTE_NORMAL
				
				mov 	byte ptr [esi],':'
				
				pop 	esi
			.endif
			
			invoke 	SetDlgItemText,hMainWnd,IDC_EDIT_PATH,edi
			invoke 	UpdateWindow,hStatusWnd
			invoke 	GetWindowPlacement,hMainWnd,ADDR wpc
			
			.if 	[wpc.showCmd]==SW_SHOWMINIMIZED
				push 	esi
				lea 	esi,ScanLogBuffer
				invoke 	OnlyFileName,offset szScanBuff,edi
				.if 	ForFix
					lea 	edx,szCln
				.else
					lea 	edx,szDel
				.endif
				invoke 	wsprintf,esi,reparg("%s: %s"),edx,eax
				invoke 	SetWindowText,hMainWnd,esi
				pop 	esi
			.else
				invoke 	SetWindowText,hMainWnd,offset szAppName
			.endif
			; -------------- ;
			
			; ------- try to clean if possible ------- ;
			.if 	FixerReady && ForFix==1
				lea 	eax,CleanFuncProc
				push 	eax
				lea 	eax,szthName
				push 	eax
				push 	edi
				call 	FixerClean
				movzx 	eax,al
				test 	eax,eax
				jnz 	@okay_okay
			.endif
			
			mov 	ebx,AppendLogConsole
			
			.if 	!DontAskDelSusp
				; ------- verify to kill suspected object!! ------- ;
				invoke 	IsSuspectedObject,ADDR szthName
				.if 	eax
					invoke 	wsprintf,pBuff,offset szObjSuspectedF,edi
					invoke 	MessageBox,hMainWnd,pBuff,offset szAppName,MB_YESNO or MB_ICONQUESTION
					.if eax!=IDYES
						scall 	ebx,reparg("Action aborted for this object :")
						scall 	ebx,edi
						jmp @nx
					.endif
				.endif
			.endif
			
			.if 	[lParam]
				; ------- check for arc file/selected delete ------- ;
				invoke 	IsArchiveRoot?,ItemIndex
				.if 	eax
					invoke 	MessageBox,hMainWnd, \
							reparg("Are You sure to delete archive file?"), \
							offset szAppName,MB_ICONQUESTION OR MB_OKCANCEL
					.if 	eax == IDOK
						invoke 	AppendLogConsole,reparg("try to delete archive file...")
						invoke 	SetFileAttributes,edi,FILE_ATTRIBUTE_NORMAL
						invoke 	DeleteFile,edi
						.if 	eax
							scall 	esi,hMainList,LVM_DELETEITEM,ItemIndex,0
							invoke 	AppendLogConsole,offset szSuccess
						.else
							invoke 	AppendLogConsole,offset szFailed
						.endif
						invoke 	UpdateArcItemList,edi
					.endif
					
					jmp @nx
				.endif
			.endif
			
			; ------- Kill it ------- ;
			invoke 	KillObjectForcely,edi
			.if 	eax
@okay_okay:
				scall 	esi,hMainList,LVM_DELETEITEM,ItemIndex,0
				.if 	ArcReady
					push 	edi
					call 	UpdateArcNumListItem
				.endif
				scall 	ebx,offset szSuccess
			.else
				mov 	[lvi.iSubItem],4
				mov 	eax,ItemIndex
				m2m		[lvi.iItem],eax
				
				scall 	ebx,offset szFailed
				
				.if 	!CleanInArc
					
					; ------- check for network path ------- ;
					cmp 	word ptr [edi],'\\'
					jne 	@F
						mov 	[lvi.pszText],leatext("Network path inaccessible or not writable media.")
						jmp 	@infthis
					@@:
					
					; ------- check for already scheduled ------- ;
					invoke 	IsAlreadyScheduled?,ItemIndex
					test 	eax,eax
					jnz		@alreadysch
					
					; ------- don't scheduled for object in unwritable media (eg. CD-ROM) ------- ;
					invoke 	IsDriveNW,edi
					jz 		@F
						scall 	ebx,offset szMediaNW
						mov 	[lvi.pszText],offset szMediaNW
						jmp 	@infthis
					@@:
					
					; ------- register to next boot kill ------- ;
					invoke 	wsprintf,offset szUtilsBuff,offset szKillfnrF,edi
					invoke 	MessageBox,hMainWnd,offset szUtilsBuff,offset szAppName,MB_YESNO or MB_ICONQUESTION
					.if 	eax==IDYES
						inc 	SomeObjectNeedReboot
					@alreadysch:
						scall 	ebx,reparg("Object scheduled to clean for next boot")
						invoke 	NextBootKillThisFile,edi
						mov 	[lvi.pszText],offset szKillScheduled						
					.else
					@cntclnthis:
						mov 	[lvi.pszText],offset szCannotCleanThis
					.endif
					; -------------- ;
				.else
					mov 	[lvi.pszText],leatext("Cannot clean this object.")
				.endif
				
			@infthis:
				lea 	eax,lvi
				scall 	esi,hMainList,LVM_SETITEM,0,eax

				
				scall 	esi,hMainList,LVM_SETCOLUMNWIDTH,4,LVSCW_AUTOSIZE_USEHEADER
			.endif
			
			@nx:
			cmp 	ItemIndex,0
			je 		@F
		jmp 	@lp
		@@:
		
	.endif
	
@endl:
	invoke 	SetCtrlDS,STATE_ENABLE
	
	StatusIdleWait

	scall 	esi,hMainList,LVM_GETITEMCOUNT,0,0
	.if 	!eax
		mov 	[LastScannedInfo.wStatus],STATUS_TAKEACTION
	.else
		invoke 	SetActionTbState,STATE_ENABLE
	.endif

	mov 	StopClean,1
	mov 	InAction,0
	mov 	ForFix,0
	
	.if 	pBuff
		vfree 	pBuff
	.endif
	
	invoke 	EnableWindow,hMainList,TRUE
	invoke 	SetWindowText,hMainWnd,offset szAppName
	
	invoke 	ExitThread,0
	ret

CleanNow endp

align 16

; ------- loader for CleanNow ------- ;
StartCleanNow proc lParam:DWORD
	LOCAL 	thID:DWORD
	
	
	mov 	StopClean,0
	
	invoke 	CreateThread,0,0,ADDR CleanNow,[lParam],0,ADDR thID
	invoke 	CloseHandle,eax
	
	ret

StartCleanNow endp

align 16

InitLastScannedBuffer proc uses edi esi ebx ecx edx
	.if 	ScanLogReady
		invoke 	AppendLogConsole,reparg("Initializing buffer LSB...")
	.endif
	.if 	LastScannedPath
		call 	FreeLastScannedPathBuffer
	.endif
	.if 	ScanLogReady
		invoke 	AppendLogConsole,ADDR szInitSuckses
	.endif
	ret
InitLastScannedBuffer endp

align 16

InsertLastScannedPathBuffer proc uses edi esi ebx ecx edx lpszPath:DWORD
	LOCAL 	len:DWORD
	LOCAL 	NewBuffer,NewSize:DWORD
	

	.if 	!LastScannedPath	; ------- first initial ------- ;
		
		strlen lpszPath
		
		inc 	eax
		mov 	LastScannedPathSize,eax
		valloc 	eax
		.if 	eax
			mov 	LastScannedPath,eax
			
			; ------- first path ------- ;
			
			strlen lpszPath
			
			inc 	eax
			invoke 	lstrcpyn,LastScannedPath,lpszPath,eax
			jmp 	@endl
		.else
			mErrorLog	"Cannot allocate memory for LastScannedPath"
		.endif
	.endif
	
	.if 	LastScannedPath
		
		; ------- resize buffer ------- ;
		
		strlen lpszPath
		
		mov 	ecx,LastScannedPathSize
		add 	ecx,eax
		inc 	ecx
		inc 	eax
		mov 	len,eax
		mov 	NewSize,ecx
		valloc 	ecx
		.if 	eax
			mov 	NewBuffer,eax
			invoke 	MyCopyMem,NewBuffer,LastScannedPath,LastScannedPathSize
			mov 	ecx,NewBuffer
			add 	ecx,LastScannedPathSize
			invoke 	lstrcpyn,ecx,lpszPath,len
			
			; ------- flush old buffer ------- ;
			vfree 	LastScannedPath
			
			; ------- renew handle and size ------- ;
			push 	NewBuffer
			pop 	LastScannedPath
			push 	NewSize
			pop 	LastScannedPathSize
		.endif
	.endif
	
@endl:

	ret

InsertLastScannedPathBuffer endp

align 16

FreeLastScannedPathBuffer proc
	
	.if 	LastScannedPath
		vfree	LastScannedPath
		mov 	LastScannedPath,0
		mov 	LastScannedPathSize,0
	.endif
	
	ret

FreeLastScannedPathBuffer endp

align 16

; ------- thread ------- ;
QuickScan proc uses ebx lParam:DWORD
	
	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	
	invoke 	MyZeroMemory,ADDR lBuff,MAX_PATH

	mov 	ebx,AppendLogConsole
	
	invoke 	BrowseForFolder,hMainWnd,ADDR lBuff,ADDR szAppName,reparg("Choose location to scan"),0
	.if 	eax
		
		lea 	eax,lBuff
		.if 	byte ptr [eax]
			invoke 	SetCtrlDS,STATE_DISABLE
			invoke 	SetActionTbState,STATE_DISABLE
			
			scall 	ebx,reparg("Scan started uses QuickScan mode")
			scall 	ebx,reparg("Initializing SLS...")
			
			; ------- Init ------- ;
			call 	InitScan
			call 	InitLastScannedBuffer
			call 	SetAllMainCtrlState
			
			scall 	ebx,offset szInitCompleted
			scall 	ebx,reparg("Buffering...")
			
			StatusBuffering 	; <-- Set status ;
			
			
			lea 	eax,lBuff
			push 	eax
			call 	GetAllFilesCountFromThisPath
			
			.if 	AllFilesCount
				
				invoke 	SendMessage,hMainProgBar,PBM_SETRANGE32,0,AllFilesCount
				
				scall 	ebx,offset szDone
				StatusChecking	; <-- Set status ;
				
				scall 	ebx,reparg("Checking for path :")
				lea 	eax,lBuff
				scall 	ebx,eax
				
				; ------- processing ------- ;
				invoke 	CheckThisPath,ADDR lBuff
				
				; ------- Save result ------- ;
				invoke 	SaveResult,ADDR lBuff
				.if 	StopScan
					invoke 	SetDlgItemText,hMainWnd,IDC_EDIT_PATH,ADDR szCheckStoped
					invoke 	SendMessage,hMainProgBar,PBM_SETPOS,0,0
				.else
					invoke 	SetDlgItemText,hMainWnd,IDC_EDIT_PATH,ADDR szCheckComplete
				    invoke 	wsprintf,ADDR szPercentBuff,ADDR szPercentF,100
				    invoke 	SetWindowText,hTxtMainPercent,ADDR szPercentBuff
					invoke 	SendMessage,hMainProgBar,PBM_SETPOS,AllFilesCount,0
				.endif
				
				scall 	ebx,offset szFlushBuffer
				
				mov 	StopScan,1
				StatusIdleWait 		; <-- Set status ;
				
				.if 	DetectedThreatsCnt
					invoke 	SetMainTxtStatus,STATUS_DETECTED
					invoke 	SetActionTbState,STATE_ENABLE
					scall 	ebx,offset szCheckCmpltDC
				.else
					invoke 	SetMainTxtStatus,STATUS_CLEAN
					invoke 	SetActionTbState,STATE_DISABLE
					scall 	ebx,offset szCheckCmpltNDC
				.endif
				
			.else
				mov 	InScanning,0
				scall 	ebx,offset szDone
				StatusIdle	; <-- Set status ;
			.endif
			scall 	ebx,offset szScanLogReady
		.endif
	.endif
	
	invoke 	SetCtrlDS,STATE_ENABLE
	; ------- check and shutdown if defined ------- ;
	invoke 	ExitThread,0
	ret

QuickScan endp

align 16

; ------- start quick scan (loader) ------- ;
StartQuickScan proc
	
	LOCAL 	thID:DWORD
	
	invoke 	SendMessage,hMainList,LVM_DELETEALLITEMS,0,0
	invoke 	CreateThread,0,0,ADDR QuickScan,0,0,ADDR thID
	invoke 	CloseHandle,eax
	
	ret

StartQuickScan endp

align 16

; ------- Scan single file procedure ------- ;
ScanSingleFile proc uses ebx esi lParam:DWORD
	LOCAL 	of:OPENFILENAME
	LOCAL 	szFileToScan[MAX_PATH+1]:BYTE
	LOCAL 	TDetc:DWORD
	LOCAL 	sSingle:DWORD

	; ------- seh installation ------- ;
	SehBegin	__ssf
	
	mov 	ebx,MyZeroMemory
	
	lea 	eax,of
	scall 	ebx,eax,sizeof OPENFILENAME
	lea 	eax,szFileToScan
	scall 	ebx,eax,MAX_PATH
	lea 	eax,TimeEndScan
	scall 	ebx,eax,sizeof SYSTEMTIME
	lea 	eax,TimeTakeA
	scall 	ebx,eax,sizeof SYSTEMTIME
	
	mov 	[of.lStructSize],sizeof OPENFILENAME
	m2m 	[of.hwndOwner],hMainWnd
	m2m 	[of.hInstance],hInstance
	lea 	eax,szMaskAllFile
	mov 	[of.lpstrFilter],eax
	lea 	eax,szFileToScan
	mov 	[of.lpstrFile],eax
	
	.if 	TimeForBlind
		lea 	eax,szRandomString
		mov 	[of.lpstrTitle],eax
	.else
		mov 	[of.lpstrTitle],leatext("Choose file to check")
	.endif
	
	mov  	[of.nMaxFile],MAX_PATH
	invoke 	GetOpenFileName,ADDR of
	
	mov 	TDetc,0
	invoke 	MyZeroMemory,ADDR gTFI,sizeof THREATFULLINFO
	lea 	eax,szFileToScan
	.if 	byte ptr [eax]
		
		mov 	ebx,AppendLogConsole
		
		; ------- let's check ------- ;		
		scall 	ebx,reparg("Scan started with single file mode")
		
		lea 	edx,LastScannedInfo
		assume 	edx:ptr LASTSCANNEDINFO
		lea 	ecx,[edx].szLocation
		lea 	edx,szSingleScan
		invoke 	lstrcmp,ecx,edx
		assume 	edx:nothing
		.if 	!zero?
			mov 	sSingle,0
			call 	InitLastScannedBuffer
		.else
			mov 	sSingle,1
		.endif
		
		call 	InitScan
		invoke 	SetCtrlDS,STATE_DISABLE
		invoke 	SetActionTbState,STATE_DISABLE
		
		scall 	ebx,reparg("try to scan file :")
		lea 	eax,szFileToScan
		scall 	ebx,eax
		
		mov 	esi,SetMainTxtStatus
		
		mov 	SingleCheck,1
		invoke 	CheckThisFile,ADDR szFileToScan,ADDR gTFI ;,0
		.if 	eax
			scall 	esi,STATUS_DETECTED
			invoke  LvInsertTFIItem,ADDR gTFI
			invoke 	SetActionTbState,STATE_ENABLE
			inc 	TDetc
			scall 	ebx,offset szCheckCmpltDC
		.else
			scall 	esi,STATUS_CLEAN
			invoke 	SetActionTbState,STATE_DISABLE
			scall 	ebx,offset szCheckCmpltNDC
			.if 	!FileScanAborted
				invoke 	MessageBox,hMainWnd,reparg("File is clean..."),ADDR szAppName,MB_OK
			.endif
		.endif
		
		mov 	SingleCheck,0
		mov 	StopScan,1
		StatusIdleWait
		invoke 	SetWindowText,hMainEditPath,offset szKosong
		
		; ------- Save result ------- ;
		lea 	edx,LastScannedInfo
		assume 	edx:ptr LASTSCANNEDINFO
		
		lea 	ecx,[edx].szLocation
		push 	edx
		lea		edx,szSingleScan
		invoke 	lstrcpy,ecx,edx
		pop 	edx
		mov 	[edx].wFinished,1
		.if 	sSingle
			inc 	[edx].dwFileScanned
		.else
			mov 	[edx].dwFileScanned,1
		.endif
		mov 	eax,TDetc
		.if 	sSingle
			add 	[edx].dwThreatsDetected,eax
		.else
			mov 	[edx].dwThreatsDetected,eax
		.endif
		.if 	eax
			mov 	[edx].wStatus,STATUS_NOTTAKEACTION
		.endif
		mov 	[edx].lpFailedArray,0
		
		lea 	eax,szFileToScan
		invoke 	InsertLastScannedPathBuffer,eax
		
		assume 	edx:nothing
		
		call 	SetStatusClrTtl
	.endif
	
	; ------- seh trap ------- ;
	SehTrap 	__ssf
		ErrorDump 	"ScanSingleFile",offset ScanSingleFile,offset szAnsavStuffasm
	SehEnd		__ssf
	
	invoke 	SetCtrlDS,STATE_ENABLE
	mov 	InScanning,0
	
	cmp 	MainScanButton,2
	je 		@F
		invoke 	ExitThread,0
	@@:
	
	ret

ScanSingleFile endp

align 4

StartScanSingleFile proc
	
	LOCAL 	thID:DWORD
	
	invoke 	CreateThread,0,0,offset ScanSingleFile,0,0,ADDR thID
	invoke 	CloseHandle,eax
	
	ret

StartScanSingleFile endp

align 4

SaveResult proc uses esi lpszLastObject:DWORD
	
	mov 	InScanning,0
	
	; ------- Save result ------- ;
	lea 	esi,LastScannedInfo
	assume 	esi:ptr LASTSCANNEDINFO
	
	lea 	eax,[esi].szLocation
	invoke 	lstrcpyn,eax,lpszLastObject,MAX_PATH
	mov 	eax,MainPBPos
	mov 	[esi].dwFileScanned,eax
	mov 	eax,DetectedThreatsCnt
	mov 	[esi].dwThreatsDetected,eax
	mov 	eax,STATUS_NOTTAKEACTION
	mov 	[esi].wStatus,ax
	mov 	[esi].lpFailedArray,0
	mov 	eax,StopScan
	RevEax

	mov 	[esi].wFinished,ax
	assume 	esi:nothing
	
	; ------- time ------- ;
	invoke 	GetLocalTime,ADDR TimeEndScan
	
	; ------- take a time ------- ;
	xor 	eax,eax
	mov 	ax,[TimeEndScan.wMilliseconds]
	sub 	ax,[TimeBeginScan.wMilliseconds]
		.if 	sign?
			neg 	ax
		.endif
		mov 	[TimeTakeA.wMilliseconds],ax
		
	mov 	ax,[TimeEndScan.wSecond]
	sub 	ax,[TimeBeginScan.wSecond]
		.if 	sign?
			neg 	ax
		.endif
		mov 	[TimeTakeA.wSecond],ax
		
	mov 	ax,[TimeEndScan.wMinute]
	sub 	ax,[TimeBeginScan.wMinute]
		.if 	sign?
			neg 	ax
		.endif
		mov 	[TimeTakeA.wMinute],ax
		
	mov 	ax,[TimeEndScan.wHour]
	sub 	ax,[TimeBeginScan.wHour]
		.if 	sign?
			neg 	ax
		.endif
		mov 	[TimeTakeA.wHour],ax
	
	.if 	ShowResult && !StopScan
		call 	ViewResult
	.endif
	
	; ------- clean up temp arc ------- ;
	invoke 	GenocideThisPath,offset szAnsavTempWorkDir
	
	call 	CheckAndShutdown
	
	ret

SaveResult endp

align 16

LoadComponen 	proc uses ebx

	; ------- seh installation ------- ;
	SehBegin 	__lc

	mov 	_WhatThePackerEx,0
	mov 	_PackerType2String,0
	invoke 	LoadLibrary,ADDR szanPdetectorPath
	.if 	eax
		mov 	ebx,eax
		mov 	hAnpDetector,eax
		invoke	GetProcAddress,eax,ADDR szWhatThePackerEx
		.if 	eax
			mov 	_WhatThePackerEx,eax
		.else
			jmp 	@err
		.endif
		invoke 	GetProcAddress,ebx,ADDR szPackerType2String
		.if 	eax
			mov 	_PackerType2String,eax
		.else
			jmp 	@err
		.endif
	.else
	@err:
		ViewError	0,"Cannot load for ansav componen anPdetector.dll, this module is needed for scan level 3 to work correctly."
	.endif

	.if		EnableArchiveScan
		; ------- archive ready? ------- ;
		call 	ArcInit
		mov 	ArcReady,eax
	.endif
	
	mov 	FixerClean,0
	mov 	FixerReady,0
	mov 	hFixerMod,0
	call 	FixerInit
	mov 	FixerReady,eax
	
	; ------- seh trapper ------- ;
	SehTrap 	__lc
		ErrorDump 	"LoadComponen",offset LoadComponen,offset szAnsavStuffasm
	SehEnd 		__lc

	ret
LoadComponen	endp

align 16

.data
	szBlindCnt	db "BlindCnt",0
.code


BlindSucker	proc uses ebx
	LOCAL 	lbrw:DWORD
	LOCAL 	lBuff[256]:BYTE
	
	; ------- seh installation ------- ;
	SehBegin 	__bs
	
	call 	GetTickCount
	invoke 	nseed,eax
	
	; ------- check for key ------- ;
	invoke 	GetModuleHandle,reparg("user32.dll")
	.if 	eax
		lea 	edx,lBuff
		mov 	dword ptr [edx],'AteG' ;"GetAsyncKeyState"
		mov 	dword ptr [edx+4],'cnys'
		mov 	dword ptr [edx+8],'SyeK'
		mov 	dword ptr [edx+12],'etat'
		mov 	byte ptr [edx+12+4],0
		invoke 	GetProcAddress,eax,edx
		.if 	!eax
			SehPop
			return_0
		.endif
	.endif
	scall 	eax,VK_B
	.if 	eax
		jmp 	@blind
	.endif
	
	invoke 	MyZeroMemory,ADDR lBuff,256
	mov 	lbrw,0
	invoke 	GetPrivateProfileString,ADDR  szAnsavName,ADDR szBlindCnt,ADDR lbrw,ADDR lBuff,256,ADDR szAnsavIniPath
	cmp 	lBuff[0],0
	je		@writeit
	invoke 	atodw,ADDR lBuff
	mov		ebx,eax
	add 	ebx,5000
	call 	GetTickCount
	.if 	eax < ebx
		sub 	ebx,5000*2
		cmp 	eax,ebx
		jb		@writeit
@blind:
		; ------- time for blind all sucker ------- ;
		invoke 	Random,10
		add 	eax,20 ; min
		invoke 	MakeRandomString,ADDR szRandomString,eax
		invoke 	MakeRandomString,ADDR szAppName,5
		mov 	TimeForBlind,1
		jmp 	@owrite
	.else
@writeit:
		mov 	TimeForBlind,0
@owrite:
		; set it last
		call 	GetTickCount
		lea 	ebx,lBuff
		invoke 	wsprintf,ebx,ADDR szdTosF,eax
		invoke 	WritePrivateProfileString,ADDR szAnsavName,ADDR szBlindCnt,ebx,ADDR szAnsavIniPath
		
	.endif
	
	; ------- seh trapper ------- ;
	SehTrap 	__bs
		ErrorDump 	"BlindSucker",offset BlindSucker,offset szAnsavStuffasm
	SehEnd		__bs
	
	ret

BlindSucker endp

align 16

ShowLogWindow proc
	
	invoke 	IsWindow,hConsoleLogDlg
	.if 	eax
		invoke 	ShowWindow,hConsoleLogDlg,SW_SHOW
		invoke 	FlashWindow,hConsoleLogDlg,0
		invoke 	SetForegroundWindow,hConsoleLogDlg
	.else
		call 	StartConsoleLogDlgProc
	.endif
	ret

ShowLogWindow endp

align 16

CheckInstalled proc
	LOCAL 	mi:MENUITEMINFO

	invoke 	MyZeroMemory,ADDR mi,sizeof MENUITEMINFO
	
	mov 	[mi.cbSize],sizeof MENUITEMINFO
	mov 	[mi.fMask],MIIM_DATA or MIIM_ID or MIIM_STATE or MIIM_SUBMENU or MIIM_TYPE or MIIM_CHECKMARKS
	mov 	[mi.fType],MFT_STRING
	mov 	[mi.wID],IDM_HELP_INSTALL
	
	call 	IsAlreadyInstalled?
	.if 	eax
		mov 	[mi.dwTypeData],reparg("Uninstall Ansav")
	.else
		mov 	[mi.dwTypeData],reparg("Install Ansav")
	.endif
	invoke 	GetSubMenu,hMainMenu,4
	lea 	ecx,mi
	invoke 	SetMenuItemInfo,eax,IDM_HELP_INSTALL,FALSE,ecx
	
	ret
CheckInstalled endp

szExvdbErr db "ERROR : In uncompressing external database, vdb.dat file corrupted.",13,10
			db "Please update ANSAV immediately at www.ansav.com",13,10
			db "Do you want to run ANSAV in limited database??",0

Align 4

LoadExVdb proc uses edi esi ebx
	LOCAL 	lbrw:DWORD
	LOCAL 	RealSize,DstMem:DWORD
	
	; ------- seh installation ------- ;
	SehBegin	__lev
	
	invoke 	CreateFile,offset szVdbDat,
			GENERIC_READ,FILE_SHARE_READ,
			0,OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,0
	.if 	eax != -1
		mov 	esi,eax
		
		invoke 	GetFileSize,esi,0
		.if 	eax
			mov 	ebx,eax
			valloc 	ebx
			.if 	eax
				mov 	edi,eax
				
				invoke 	ReadFile,esi,edi,ebx,ADDR lbrw,0
				.if 	eax
					
					
					; ------- unpack it ------- ;
					m2m 	RealSize,[edi.EXVDBINFO].RealSize
					add 	RealSize,sizeof EXVDBINFO
					valloc 	RealSize
					.if 	eax
						mov 	DstMem,eax
						
						; ------- seh ------- ;
						SehBegin __ap_depack
						
						mov 	ecx,eax
						add 	ecx,sizeof EXVDBINFO
						mov 	eax,edi
						add 	eax,sizeof EXVDBINFO
						invoke 	aP_depack_asm_fast,eax,ecx
						
						SehTrap 	__ap_depack
							vfree 	DstMem
							vfree 	edi
							invoke 	CloseHandle,esi
							invoke 	MessageBox,0,offset szExvdbErr,offset szAppName,MB_ICONERROR
							SehPop
							return_0
						SehEnd 		__ap_depack
						
						invoke 	MyCopyMem,DstMem,edi,sizeof EXVDBINFO
						
						invoke 	VirtualProtect,DstMem,RealSize,PAGE_READONLY,ADDR lbrw
						vfree 	edi
						mov2 	ExternalVdb,DstMem
						mov2	ExternalVdbSize,RealSize
						invoke 	CloseHandle,esi
						SehPop
						return_0
					.else
						xor 	eax,eax
						mov 	ExternalVdb,eax
						mov 	ExternalVdbSize,eax
						
						ViewError	0,"Cannot allocate memory for externeal database"
					.endif
					; -------------- ;
					
					;invoke 	VirtualProtect,edi,ebx,PAGE_READONLY,ADDR lbrw
					invoke 	CloseHandle,esi
					SehPop
					return_0
				.endif
				
				vfree 	edi
			.else
				ViewError	hMainWnd,"Cannot allocate memory for external threats database."
			.endif
		.endif
		invoke 	CloseHandle,esi
	.endif
	
	; ------- seh trapper ------- ;
	SehTrap 	__lev
		ErrorDump	"LoadExVdb",offset LoadExVdb,offset szAnsavStuffasm
	SehEnd		__lev
	
	ret

LoadExVdb endp

Align 4

CloseExVdb proc
	
	.if 	ExternalVdb
		vfree 	ExternalVdb
	.endif
	ret

CloseExVdb endp

Align 4

Readme proc uses edi esi ebx
	LOCAL 	lbrw:DWORD
	
	lea 	ebx,szReadmeTxt
	invoke 	ShellExecute,hMainWnd,ADDR szOpen,ebx,0,ADDR szMyDir,SW_SHOWMAXIMIZED
	
@endl:
	ret

Readme endp

Align 4

;0023F90C   0000000C  |HookType = WH_CALLWNDPROCRET

Stealth proc uses esi edi
	
	cmp 	NoStealth,1
	jne 	@F
		return_0
	@@:
	
	invoke 	CreateFileMapping,-1,0,PAGE_READWRITE,0,350,reparg("STEALTHENGINE")
	.if 	!eax
		return_0
	.endif
	mov 	hStealthfMap,eax
	invoke 	MapViewOfFile,eax,0F001Fh,0,0,0
	.if 	!eax
		invoke 	CloseHandle,hStealthfMap
		return_0
	.endif
	
	mov 	hStealthmMap,eax
	mov 	esi,eax
	invoke 	GetCurrentProcessId
	mov 	[esi.CEST].hPID,eax
	invoke 	GetCurrentThreadId
	mov 	[esi.CEST].hTHID,eax
	m2m		[esi.CEST].hMainWnd,hMainWnd
	m2m		[esi.CEST].hWnd2,hMainWnd
	
	cmp 	szSteDll2[0],0
	jne 	@skipgenste
	
	; ------- cleanup old ste ------- ;
	call 	CleanupSteTmp
@lainnya:
	; ------- generate ste name ------- ;
	cld
	lea 	edi,szSteDll2
	invoke 	lstrcpyn,edi,offset szWinDir,MAX_PATH
	invoke 	TruePath,edi
	strlen  edi
	add 	edi,eax
	mov 	ecx,7
	@@:
		push 	ecx
		invoke 	Random,25
		add 	eax,65
		stosb
		pop 	ecx
	loop	@B
	mov 	eax,'lld.'
	stosd
	xor al,al
	stosb
	invoke 	CopyFile,offset szSteDll, offset szSteDll2,1
	test 	eax,eax
	jz 		@lainnya
		
		; ------- save working ste name to config.ini ------- ;
		analloc	MAX_PATH+1
		.if 	eax
			mov esi,eax
			invoke 	anCrypto,esi,offset szSteDll2
			
			invoke 	WritePrivateProfileString, \
					offset szAnsavName, \
					offset szSteKey,esi, \
					offset szAnsavIniPath
			anfree	esi
		.endif
		
	; -------------- ;
	
@skipgenste:
	.if 	!hStealthHookMod
		invoke 	LoadLibrary,offset szSteDll2
		mov 	hStealthHookMod,eax
	.endif
	mov 	eax,hStealthHookMod
	invoke 	GetProcAddress,eax,reparg("hook")
	.if 	eax
		
		.if 	!hStealthHook
			invoke 	SetWindowsHookEx,WH_CALLWNDPROCRET,eax,hStealthHookMod,0
			mov 	hStealthHook,eax
		.endif
		
	.endif
	
@endl:
	ret

Stealth endp

Align 4

UnStealth proc uses edi
	
	.if 	hStealthHook
		invoke 	UnhookWindowsHookEx,hStealthHook
		mov 	hStealthHook,0
		
		lea 	edi,szAppName
		
		strlen edi
		
		mov 	ecx,eax
		;[stealth]
		
		@@:
			cmp 	dword ptr [edi],'ets['
			je		@F
			dec 	ecx
			inc 	edi
			jecxz	@nx
			jmp 	@B
		@@:
		sub 	edi,2
		xor 	al,al
		stosb
		invoke 	SetWindowText,hMainWnd,offset szAppName
		@nx:
	.endif
	.if 	hStealthmMap
		invoke 	UnmapViewOfFile,hStealthmMap
	.endif
	.if 	hStealthfMap
		invoke 	CloseHandle,hStealthfMap
	.endif
	mov 	eax,hStealthHookMod
	.if 	eax
		invoke 	FreeLibrary,eax
		mov 	hStealthHookMod,0
	.endif
	
	ret

UnStealth endp

Align 4

MakeUnkillable proc
	LOCAL 	cest:CEST
	
	invoke 	MyZeroMemory,ADDR cest,sizeof CEST
	
	invoke 	GetModuleHandle,offset szAnhookerDll
	.if 	eax
		invoke 	GetProcAddress,eax,offset sz__cest
		.if 	eax
			push 	eax
			invoke 	GetCurrentProcessId
			pop 	edx
			mov 	[cest.hPID],eax
			lea 	eax,cest
			push 	eax
			call 	edx
		.endif
	.endif
	
	ret

MakeUnkillable endp

Align 16

DontHookme proc
	
	invoke 	GetModuleHandle,offset szAnhookerPath
	.if 	eax
		invoke 	GetProcAddress,eax,offset sz__dhm
		.if 	eax
			call 	eax
		.endif
	.endif
	ret

DontHookme endp


Align 16 

IsAnsavRun? proc uses esi edi
	
	LOCAL 	hSnap,MyPID:DWORD
	LOCAL 	lpe32:PROCESSENTRY32
	LOCAL 	cp[32]:BYTE
	LOCAL 	retv,lbrw:DWORD
	
	invoke 	MyZeroMemory,ADDR lpe32,sizeof PROCESSENTRY32
	invoke 	MyZeroMemory,ADDR cp,32
	
	mov 	retv,0	
	call 	GetCurrentProcessId
	mov 	MyPID,eax
	
	mov 	[lpe32.dwSize],sizeof PROCESSENTRY32
	
	invoke 	CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS,0
	.if 	eax
		mov 	hSnap,eax
		invoke 	Process32First,hSnap,ADDR lpe32
		.while 	eax
			mov 	eax,lpe32.th32ProcessID
			.if 	eax!=MyPID
				mov 	esi,IsAnsavRun?
				lea 	edi,cp
				lea 	edx,lbrw
				invoke 	Toolhelp32ReadProcessMemory,
						[lpe32.th32ProcessID],esi,edi,32,edx
				cmp 	dword ptr [edi],0
				je		@nx
				
				mov 	ecx,32
				shr 	ecx,2
				repe 	cmpsd
				.if 	!ecx
					inc 	retv
				.endif
			.endif
			@nx:
			invoke 	Process32Next,hSnap,ADDR lpe32
		.endw
		invoke 	CloseHandle,hSnap
	.endif
	
	mov 	eax,retv
	ret

IsAnsavRun? endp

align 4

GetItemNum proc uses edi lpszIp:DWORD
	
	LOCAL 	lvi:LV_ITEM
	LOCAL 	iItem:DWORD
	LOCAL 	buff:DWORD
	LOCAL 	retv:DWORD
	
	invoke 	MyZeroMemory,ADDR lvi,sizeof LV_ITEM
	mov 	iItem,0
	mov 	retv,0
	
	mov 	buff,0
	valloc 	(MAX_PATH*4)+1
	.if 	!eax
		return_0
	.endif
	mov 	buff,eax
	
	mov 	[lvi.imask],LVIF_TEXT
	mov 	[lvi.iSubItem],1
	mov2 	[lvi.pszText],buff
	mov 	[lvi.cchTextMax],MAX_PATH
	
	mov 	edi,SendMessage
	
	scall 	edi,hMainList,LVM_GETITEMCOUNT,0,0
	.while 	eax
		mov 	iItem,eax
		dec 	eax
		mov 	[lvi.iItem],eax
		lea 	eax,lvi
		invoke 	SendMessage,hMainList,LVM_GETITEM,0,eax
		mov 	edi,buff
		.if 	byte ptr [edi]
			
			strlen edi
			
			mov 	ecx,eax
			cld
			mov 	al,':'
			
			push 	lpszIp
			push 	edi
				mov 	edi,buff
				repne scasb
				repne scasb
				jecxz @F
				dec edi
				mov byte ptr [edi],0
				@@:
			
			call 	lstrcmpi
			.if 	zero?
				inc 	retv
			.endif
		.endif
		
		dec 	iItem
		mov 	eax,iItem
	.endw
	
@endl:
	.if 	buff
		vfree buff
	.endif
	
	mov 	eax,retv
	ret

GetItemNum endp

align 4

UpdateArcNumListItem proc uses edi lpszArcItem:DWORD
	
	LOCAL 	lvi:LV_ITEM
	LOCAL 	iItem:DWORD
	LOCAL 	buff,buff2:DWORD
	LOCAL 	lBuff[50]:BYTE
	LOCAL 	retv:DWORD
	
	; ------- seh installtion ------- ;
	SehBegin	__uanli
	
	sub 	eax,eax
	mov 	buff,eax
	mov 	buff2,eax
	mov 	retv,eax
	
	analloc (MAX_PATH*4)+1
	.if 	!eax
		SehPop
		return_0
	.endif
	mov 	buff,eax
	
	analloc (MAX_PATH*4)+1
	.if 	!eax
		anfree buff
		SehPop
		return_0
	.endif
	mov 	buff2,eax
	
	mov 	edi,buff2
	push 	edi
	invoke 	lstrcpy,edi,lpszArcItem
	cld
	mov 	ecx,MAX_PATH
	mov 	al,':'
	repne	scasb
	repne	scasb
	dec 	edi
	xor 	al,al
	stosb
	pop 	edi
	
	invoke 	MyZeroMemory,ADDR lvi,sizeof LV_ITEM
	
	mov 	[lvi.imask],LVIF_TEXT
	mov 	[lvi.iSubItem],1
	mov2 	[lvi.pszText],buff
	mov 	[lvi.cchTextMax],MAX_PATH
	
	mov 	iItem,0
	invoke 	SendMessage,hMainList,LVM_GETITEMCOUNT,0,0
	
	.while 	eax
		mov 	iItem,eax
		dec 	eax
		mov 	[lvi.iItem],eax
		invoke	SendMessage,hMainList,LVM_GETITEM,iItem,ADDR lvi
		.if 	buff[0]
			
			invoke 	lstrcmpi,buff,buff2
			.if 	zero?
				
				invoke 	GetItemNum,edi
				dec 	eax
				.if 	eax
					invoke 	wsprintf,ADDR lBuff,offset szThreatInsideF,eax
					mov 	[lvi.iSubItem],0
					lea 	eax,lBuff
					mov 	[lvi.pszText],eax
					invoke 	SendMessage,hMainList,LVM_SETITEM,iItem,ADDR lvi
				.else
					dec 	iItem
					invoke 	SendMessage,hMainList,LVM_DELETEITEM,iItem,0
					mov 	retv,2
				.endif
				invoke 	SetWindowText,hMainEditPath,offset szKosong
				jmp 	@endl
			.endif
			
		.endif	
		
		dec 	iItem
		mov 	eax,iItem
	.endw

@endl:

	; ------- seh trapper ------- ;
	SehTrap 	__uanli
		ErrorDump 	"UpdateArcNumListItem",offset UpdateArcNumListItem,offset szAnsavStuffasm
	SehEnd 		__uanli

	.if 	buff
		anfree 	buff
		mov 	buff,0
	.endif
	.if 	buff2
		anfree	buff2
		mov 	buff2,0
	.endif
	
	
	mov 	eax,retv
	ret

UpdateArcNumListItem endp

align 4

UpdateArcItemList proc uses esi lpszObject:DWORD
	
	LOCAL 	lvi:LV_ITEM
	LOCAL 	lbuff[MAX_PATH+1]:BYTE
	LOCAL 	lItem:DWORD
	
	; ------- seh installation ------- ;
	SehBegin	__uail
	
	lea 	esi,lvi
	invoke 	MyZeroMemory,esi,sizeof LV_ITEM
	lea 	edi,lbuff

	
	mov 	[lvi.imask],LVIF_TEXT
	mov 	[lvi.iSubItem],1
	mov 	[lvi.pszText],edi
	mov 	[lvi.cchTextMax],256
	
	invoke 	SendMessage,hMainList,LVM_GETITEMCOUNT,0,0
	.if 	eax
		mov 	lItem,eax
		
		.while 	lItem!=-1
			
			invoke 	MyZeroMemory,edi,MAX_PATH
			
			mov 	eax,lItem
			mov 	[lvi.iItem],eax
			invoke 	SendMessage,hMainList,LVM_GETITEM,eax,esi
			
			.if 	!byte ptr [edi]
				jmp 	@nx
			.endif
			
			mov 	al,':'
			mov 	ecx,MAX_PATH
			cld
			push 	edi
				repne scasb
				.if 	!zero?
					pop 	edi
					jmp 	@nx
				.endif
				repne scasb
				.if 	!zero?
					pop 	edi
					jmp 	@nx
				.endif
				dec 	edi
				mov 	byte ptr [edi],0
			pop 	edi
			
			invoke 	lstrcmpi,edi,lpszObject
			.if 	zero?
				invoke 	SendMessage,hMainList,LVM_DELETEITEM,lItem,0
			.endif
			
			
			@nx:
			dec 	lItem
		.endw		
		
	.endif

	; ------- seh trapper ------- ;
	SehTrap 	__uail
		ErrorDump	"UpdateArcItemList",offset UpdateArcItemList,reparg("AnsavStuff.asm")
	SehEnd 		__uail	
	
	ret

UpdateArcItemList endp

align 16

FixerInit proc
	
	LOCAL 	retv:DWORD
	mov 	retv,0
	
	invoke 	LoadLibrary,offset szFixerFx
	.if 	eax
		mov 	hFixerMod,eax
		invoke 	GetProcAddress,eax,reparg("Clean")
		.if 	eax
			mov 	FixerClean,eax
			mov 	retv,eax
		.endif
	.endif
	mov 	eax,retv
	ret

FixerInit endp

align 4

ScanOnlyDir proc uses edi esi lParam:DWORD

	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	
	; ------- seh installation ------- ;
	SehBegin 	__sowd
	
	lea 	edi,lBuff
	invoke 	lstrcpyn,edi,lParam,MAX_PATH

	invoke 	SetCtrlDS,STATE_DISABLE
	invoke 	SetActionTbState,STATE_DISABLE
	
	call 	InitScan
	
	mov 	esi,AppendLogConsole
	
	scall 	esi,offset szBuffering
	; ------- prepare buffer for last scanned path ------- ;
	call 	InitLastScannedBuffer
	call 	SetAllMainCtrlState
	
	mov 	InScanning,1
	
	StatusBuffering 	; <-- Set status ;
	push 	edi
	call 	GetAllFilesCountFromThisPath
	
	invoke 	SendMessage,hMainProgBar,PBM_SETRANGE32,0,AllFilesCount
	StatusChecking 		; <-- Set status ;
	
	invoke 	CheckThisPath,edi
	.if 	!StopScan
		invoke 	InsertLastScannedPathBuffer,edi
	.endif

	scall 	esi,offset szFlushBuffer
	
	; ------- Save result ------- ;
	invoke 	SaveResult,edi
	
	.if 	StopScan
		invoke 	SetDlgItemText,hMainWnd,IDC_EDIT_PATH,offset szCheckStoped
		invoke 	SendMessage,hMainProgBar,PBM_SETPOS,0,0
	.else
		invoke 	SetDlgItemText,hMainWnd,IDC_EDIT_PATH,offset szCheckComplete
		invoke 	SendMessage,hMainProgBar,PBM_SETPOS,AllFilesCount,0
	    invoke 	wsprintf,ADDR szPercentBuff,ADDR szPercentF,100
	    invoke 	SetWindowText,hTxtMainPercent,ADDR szPercentBuff
	.endif
	mov 	StopScan,1
	mov 	InScanning,0
	StatusIdleWait 		; <-- Set status ;
	
	.if 	DetectedThreatsCnt
		invoke 	SetMainTxtStatus,STATUS_DETECTED
		invoke 	SetActionTbState,STATE_ENABLE
		scall 	esi,offset szCheckCmpltDC
	.else
		invoke 	SetMainTxtStatus,STATUS_CLEAN
		invoke 	SetActionTbState,STATE_DISABLE
		scall 	esi,offset szCheckCmpltNDC
	.endif
	
	scall 	esi,offset szScanLogReady
	invoke 	SetCtrlDS,STATE_ENABLE
	
	; ------- seh trapper ------- ;
	SehTrap 	__sowd
		ErrorDump 	"ScanOnlyDir", \
			offset ScanOnlyDir, \
			offset szAnsavStuffasm
	SehEnd 		__sowd
	
	invoke 	ExitThread,0
	ret

ScanOnlyDir endp

align 4

StartScanOnlyDir proc lpszDir:DWORD
	
	LOCAL thID:DWORD
	invoke 	SendMessage,hMainList,LVM_DELETEALLITEMS,0,0
	invoke 	CreateThread,0,0,offset ScanOnlyDir,lpszDir,0,ADDR thID
	mErrorTrap	eax,"Cannot create thread for ScanOnlyWindowsDirectory",@endl
	invoke 	CloseHandle,eax
@endl:
	ret

StartScanOnlyDir endp

align 16

CleanupSteTmp proc uses esi
	
	analloc MAX_PATH+1
	.if 	eax
		mov 	esi,eax
		invoke 	GetPrivateProfileString, \
				offset szAnsavName, \
				offset szSteKey, \
				offset brw, \
				esi,MAX_PATH, \
				offset szAnsavIniPath
		.if 	byte ptr [esi]
			invoke 	anCrypto,offset szSteDll2,esi
			; ------- cleanup old randomized ste name ------- ;
			invoke 	Sleep,500
			invoke 	DeleteFile,offset szSteDll2
			invoke 	MyZeroMemory,offset szSteDll2,MAX_PATH+1
		.endif
		anfree 	esi
	.endif

	ret

CleanupSteTmp endp

align 16

CFP_ALOGC equ 1001

CleanFuncProc proc flag:DWORD,ua:DWORD,ub:DWORD,uc:DWORD,ud:DWORD
	
	LOCAL 	retv:DWORD
	
	mov 	retv,1
	
	mov 	eax,flag
	.if 	eax == CFP_ALOGC
		invoke 	AppendLogConsole,ua
	.endif
	
	mov 	retv,eax
	ret

CleanFuncProc endp

align 16

ClipboardCopyObject proc uses edi esi lParam:DWORD
	
	LOCAL lvi:LV_ITEM
	LOCAL buff[MAX_PATH+1]:BYTE
	
	lea 	edi,buff
	invoke 	MyZeroMemory,edi,MAX_PATH
	lea 	esi,lvi
	invoke 	MyZeroMemory,esi,sizeof LV_ITEM

	invoke 	SendMessage,hMainList,LVM_GETNEXTITEM,-1,LVNI_SELECTED
	
	assume 	esi:ptr LV_ITEM
	mov 	[esi].imask,LVIF_TEXT
	mov 	[esi].iItem,eax
	mov 	[esi].pszText,edi
	mov 	ecx,lParam
	dec 	ecx
	mov 	[esi].iSubItem,ecx
	mov 	[esi].cchTextMax,256
	assume 	esi:nothing
	
	invoke	SendMessage,hMainList,LVM_GETITEM,0,esi
	
	cmp 	byte ptr [edi],0
	jz 		@F
		push 	edi
		call	ClipboardCopy
	@@:
	
	ret

ClipboardCopyObject endp

align 16

szKadal db "ANSAV versi ini telah kadaluarsa, dan sudah tidak efektif lagi untuk mendeteksi",13,10
		db "virus, worm dan threat-threat baru. Segera lakukan update 'help>update'",13,10
		db "atau download ANSAV versi terbaru di website resminya http://www.ansav.com",0

IsOldiest? proc uses ebx
	LOCAL 	stime:SYSTEMTIME
	LOCAL 	dTanggal,dBulan,dTahun:DWORD
	
	; ------- seh installation ------- ;
	SehBegin 	_io?
	
	m2m 	dTahun,dwRDYear
	m2m 	dBulan,dwRDMonth
	m2m 	dTanggal,dwRDDay
	
	lea 	ebx,stime
	INVOKE 	MyZeroMemory,ebx,sizeof SYSTEMTIME
	.if 	!ExternalVdb
	
	xor 	ecx,ecx
	@lp:
	    inc 	dTanggal
	    cmp 	dTanggal,31
	    jb @F
	    mov 	dTanggal,0
	    inc 	dBulan
	    cmp 	dBulan,12
	    jb @F
	    mov 	dBulan,0
	    inc 	dTahun
	  @@:
	    inc 	ecx
	    cmp 	ecx,3
	    jne 	@lp
	
	
	    invoke 	GetLocalTime,ebx
	
	    assume ebx:PTR SYSTEMTIME
	
	    mov 	eax,dTahun
	    cmp 	[ebx].wYear,ax
	    ja 		@need_update
	    jb 		@oke_oke
	    mov 	eax,dBulan
	    cmp 	[ebx].wMonth,ax
	    ja 		@need_update
	    jb 		@oke_oke
	    mov 	eax,dTanggal
	    cmp 	[ebx].wDay,ax
	    ja 		@need_update
	    jmp 	@oke_oke
	    
	    assume 	ebx:nothing
@need_update:
		 ViewError	0,offset szKadal
@oke_oke:
		
	.endif
	
	SehTrap 	_io?
		ErrorDump	"IsOldiest?",offset IsOldiest?,offset szAnsavStuffasm
	SehEnd 		_io?
	
	ret

IsOldiest? endp

szAddrAnsav db 'Found "www.ansav.com" listed in your hosts local DNS file, this warning seems ugly',13,10
			db "but this very important to make ANSAV official website accessible from your computer.",13,10
			db "Please delete or rename it then make new fresh one. Do you like ANSAV to do that?",0 
szDefHosts 	db "127.0.0.1 localhost",13,10,0

align 16

CheckEtcHost proc
	
	;C:\WINDOWS\system32\drivers\etc
	
	LOCAL 	buff[MAX_PATH+1]:BYTE
	LOCAL 	retv:DWORD
	
	; ------- seh installation ------- ;
	SehBegin 	_ceh
	
	
	mov retv,0
	
	lea 	esi,buff
	invoke 	MyZeroMemory,esi,MAX_PATH
	
	invoke 	lstrcpy,esi,offset szSysDir
	invoke 	TruePath,esi
	invoke 	lstrcat,esi,reparg("drivers\etc\hosts")
	
	invoke 	CreateFile,esi,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
	.if 	eax != -1
		mov edi,eax
		
		invoke 	GetFileSize,edi,0
		.if 	eax
			mov 	ebx,eax
			add 	ebx,8h
			
			valloc	ebx
			.if 	eax
				mov 	esi,eax
				
				invoke 	ReadFile,edi,esi,ebx,offset brw,0
				
				push 	edi
				push 	esi
				invoke 	ReplaceChar,esi,0dh,0h,ebx
				mov 	edi,esi
				; ------- find ansav.com ------- ;
				@lp:
					invoke 	lstrlen,edi
					push 	eax
					invoke 	ReplaceChar,edi,020h,0h,eax ;space
					scall 	ReplaceChar,edi,09,0h ;TAB
					xor al,al
					cld
					or ecx,-1
					repnz scasb
					invoke 	lstrcmpi,edi,reparg("ansav.com")
					.if 	zero?
						inc retv
						jmp @dah
					.endif
					invoke 	lstrcmpi,edi,reparg("www.ansav.com")

					.if 	zero?
						inc retv
						jmp @dah
					.endif
					xor al,al
					cld
					or ecx,-1
					repnz scasb
					repnz scasb
					inc edi
					cmp byte ptr [edi],0
					jne @lp
					
				; -------------- ;
				@dah:
				pop 	esi
				pop 	edi
				
				vfree 	esi
			.endif
			
		.endif
		
		invoke 	CloseHandle,edi
	.endif
	
	.if 	retv
		
		invoke 	MessageBox,0,offset szAddrAnsav,offset szAppName,MB_YESNO OR MB_ICONEXCLAMATION
		.if 	eax==IDYES
			lea 	edi,buff
			invoke 	SetFileAttributes,edi,FILE_ATTRIBUTE_NORMAL
			invoke 	DeleteFile,edi
			
			; ------- make new fresh one ------- ;
			invoke 	CreateFile,edi,GENERIC_WRITE,FILE_SHARE_WRITE,0,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0
			.if 	eax != -1
				mov esi,eax
				invoke 	lstrlen,offset szDefHosts
				invoke 	WriteFile,esi,offset szDefHosts,eax,offset brw,0
				invoke 	CloseHandle,esi
			.else
				ViewError	0,"Creation failed, make file manualy. :("
			.endif
			
		.endif
		
	.endif
	
	; ------- seh trapper ------- ;
	SehTrap 	_ceh
		ErrorDump	"CheckEtcHost",offset CheckEtcHost,offset szAnsavStuffasm
	SehEnd 		_ceh
	
	ret

CheckEtcHost endp


align 16

ProcessCommandLine proc uses esi edi
	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	
	; ------- seh installation ------- ;
	SehBegin 	__pcl
	
	invoke 	MyZeroMemory,ADDR lBuff,MAX_PATH
	
	lea 	edi,lBuff
	invoke 	GetCL,1,edi
	
	mov 	esi,lstrcmpi
	
	;MsgBox 	0,reparg("invoke 	lstrcmpi,ADDR lBuff,reparg(-setup)")	
	scall 	esi,edi,reparg("-setup")
	.if 	zero?
		mov 	incmdl,1
		call 	StartInstallDlgProc
		jmp 	@endl
	.endif
	scall 	esi,edi,reparg("-nostealth")
	.if 	zero?
		mov 	NoStealth,1
		jmp 	@endl
	.endif
	scall 	esi,edi,reparg("-dumperver")
	.if 	zero?
		mWriteError "not error, only get OS version info"
		jmp	GlobalExit
	.endif
	
	; is path?
	invoke 	GetFileAttributes,edi
	call 	GetLastError
	cmp  	eax,ERROR_PATH_NOT_FOUND
	jz 		@endl
	cmp 	eax,ERROR_FILE_NOT_FOUND
	jz 		@endl
	
	; scan it
	analloc MAX_PATH+1
	.if 	eax
		mov 	CmdLineScan,eax
		invoke 	lstrcpyn,eax,edi,MAX_PATH
		mov 	ShowResult,1
	.else
		ViewError	hMainWnd,offset szMemAllocError
	.endif 	
	
@endl:

	; ------- seh trapper ------- ;
	SehTrap 	__pcl
		ErrorDump "ProcessCommandLine",offset ProcessCommandLine,"ansav.asm"
	SehEnd 		__pcl

	ret

ProcessCommandLine endp

align 16








