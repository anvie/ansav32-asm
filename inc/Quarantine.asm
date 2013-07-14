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

; ------- Quarantine.asm ------- ;


.data?
	FQ_ACTION_RESTORE	equ 1
	FQ_ACTION_DELETE	equ 2
	FQ_ACTION_RESTOREAS	equ 3
	FQ_ACTION_DELETEALL	equ 4 
.code

align 16

; ------- Thread ------- ;
QuarantineNow proc lParam:DWORD
	
	LOCAL 	lvi:LV_ITEM
	LOCAL 	iCount,ItemIndex:DWORD
	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	LOCAL 	lBuff2[MAX_PATH+1]:BYTE
	
	mov 	InAction,1
	
	invoke 	MyZeroMemory,ADDR lvi,sizeof LV_ITEM
	invoke 	MyZeroMemory,ADDR lBuff,MAX_PATH
	invoke 	MyZeroMemory,ADDR lBuff2,MAX_PATH
	
	invoke 	AppendLogConsole,reparg("Try to quarantine all object")
	SetStatus "Quarantine object..."
	
	call 	InitQuarantine
	.if 	!eax
		invoke 	AppendLogConsole,reparg(" Cannot initializing quarantine location")
		invoke 	AppendLogConsole,reparg(" make sure quarantine loacation is writable")
		StatusIdleWait
		return_0 
	.endif
	
	invoke 	SetCtrlDS,STATE_DISABLE
	invoke 	SetActionTbState,STATE_DISABLE
	
	mov 	StopClean,0
	
	align 4
	
	invoke 	SendMessage,hMainList,LVM_GETITEMCOUNT,0,0
	.if 	eax
		mov 	iCount,eax
		
		mov 	[lvi.imask],LVIF_TEXT
		mov 	[lvi.cchTextMax],MAX_PATH
		mov 	ItemIndex,eax
		@lp:
			
			.if 	StopClean
				jmp 	@endl
			.endif
			
			dec 	ItemIndex
			m2m 	[lvi.iItem],ItemIndex
			
			align 4
			
			.if 	[lParam]
				invoke 	SendMessage,hMainList, LVM_GETITEMSTATE,ItemIndex,LVNI_SELECTED
				cmp 	eax,LVNI_SELECTED
				jne 	@nx	; <-- only for selected object ;
			.endif
			
			mov 	[lvi.iSubItem],1
			lea 	eax,lBuff
			mov 	[lvi.pszText],eax
			invoke 	SendMessage,hMainList,LVM_GETITEM,0,ADDR lvi
			lea 	eax,lBuff
			.if 	byte ptr [eax]
				
				invoke 	IsObjectInsideArc?,ADDR lBuff
				test 	eax,eax
				jnz 	@F
				invoke 	FileExist,ADDR lBuff
				.if 	eax
					@@:

					invoke 	IsRunInMemory?,ADDR lBuff
					.if 	eax
						; ------- try to kill it ------- ;
						invoke 	KillProcForcely,eax
					.endif
					
					; ------- delete item forcely ------- ;
					invoke 	AppendLogConsole,reparg("Try to quarantine this object :")
					invoke 	AppendLogConsole,ADDR lBuff
					
					; ------- format it to quarantine style ------- ;
					mov 	[lvi.iSubItem],3 ; get risk
					invoke 	SendMessage,hMainList,LVM_GETITEM,0,ADDR lvi
					invoke 	lstrcmp,ADDR lBuff,ADDR szRiskDanger
					.if 	zero?
						push 	VIRI_RISK_DANGEROUS
					.else
						invoke 	lstrcmp,ADDR lBuff,ADDR szRiskHigh
						.if 	zero?
							push 	VIRI_RISK_HIGH
						.else
							invoke 	lstrcmp,ADDR lBuff,ADDR szRiskLow
							.if 	zero?
								push 	VIRI_RISK_LOW
							.else
								invoke 	lstrcmp,ADDR lBuff,ADDR szRiskMedium
								.if 	zero?
									push 	VIRI_RISK_MEDIUM
								.else
									invoke 	lstrcmp,ADDR lBuff,ADDR szRiskVeryHigh
									.if 	zero?
										push 	VIRI_RISK_VERYHIGH
									.else
										invoke 	lstrcmp,ADDR lBuff,ADDR szRiskVeryLow
										.if 	zero?
											push 	VIRI_RISK_VERYLOW
										.else
											push 	0
										.endif 	
									.endif
								.endif
							.endif
						.endif
					.endif
					
					mov 	[lvi.iSubItem],0
					lea 	eax,lBuff2
					mov 	[lvi.pszText],eax
					invoke 	SendMessage,hMainList,LVM_GETITEM,0,ADDR lvi ; get threat name
					lea 	eax,lBuff2
					push 	eax
					mov 	[lvi.iSubItem],1
					lea 	eax,lBuff
					mov 	[lvi.pszText],eax
					invoke 	SendMessage,hMainList,LVM_GETITEM,0,ADDR lvi ; get file path
					lea 	eax,lBuff
					push 	eax
					call 	DoQuarantineThis	; <-- Quarantine now! ;
					.if 	eax
						invoke 	AppendLogConsole,ADDR szSuccess
						invoke 	SendMessage,hMainList,LVM_DELETEITEM,ItemIndex,0
						.if 	ArcReady
							lea 	eax,lBuff
							push 	eax
							call 	UpdateArcNumListItem
						.endif
					.else
						invoke 	AppendLogConsole,ADDR szFailed
					.endif
					
				.else
					invoke 	AppendLogConsole,ADDR szThisFile
					invoke 	AppendLogConsole,ADDR lBuff
					invoke 	AppendLogConsole,reparg(" Not found, quarantine failed.")
				.endif
			.endif
			
			@nx:
			cmp 	ItemIndex,0
			je 		@F
		jmp 	@lp
		@@:
		
		invoke 	SendMessage,hMainList,LVM_GETITEMCOUNT,0,0
		.if 	!eax
			; ------- good ------- ;
			mov 	[LastScannedInfo.wStatus],STATUS_TAKEACTION
			invoke 	SetActionTbState,STATE_DISABLE
		.else
			; ------- bad ------- ;
			.if 	!lParam
				invoke 	AppendLogConsole,reparg("Some object cannot quarantine!")
			.endif
		.endif
		
	.else
		invoke 	AppendLogConsole,reparg("No object to quarantine, operation aborted.")
	.endif

@endl:	
	invoke 	SetCtrlDS,STATE_ENABLE
	
	StatusIdleWait

	invoke 	SendMessage,hMainList,LVM_GETITEMCOUNT,0,0
	.if 	!eax
		mov 	[LastScannedInfo.wStatus],STATUS_TAKEACTION
	.else
		invoke 	SetActionTbState,STATE_ENABLE
	.endif
		
	mov 	StopClean,1
	mov 	InAction,0
	
	invoke 	ExitThread,0
	ret

QuarantineNow endp

Align 16

StartQuarantineNow proc lParam:DWORD
	
	LOCAL 	thID:DWORD
	
	mov 	StopClean,0
	invoke 	CreateThread,0,0,ADDR QuarantineNow,[lParam],0,ADDR thID
	invoke 	CloseHandle,eax
	
	ret

StartQuarantineNow endp

Align 16

DoQuarantineThis proc uses esi edi lpszFilePath:DWORD, lpszThName:DWORD, Risk:DWORD

	LOCAL 	nIndex,ErrOccur:DWORD
	LOCAL 	hFile,fSize,fSize2,fNewSize:DWORD
	LOCAL 	pSrcMem,pDstMem,pWorkingMem:DWORD
	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	LOCAL 	lbrw,len,tmp:DWORD
	LOCAL 	retv:DWORD


	mov 	nIndex,0
	mov 	retv,0
	mov 	lbrw,0
	mov 	ErrOccur,0
	
	xor 	edi,edi
	
	; ------- compress file first uses aPlib algoritmo by Joergen Ibsen ------- ;
	mov 	eax,lpszFilePath
	test 	eax,eax
	jz 		@endl
	
	invoke 	IsObjectInsideArc?,lpszFilePath
	.if 	!eax
		
		invoke 	IsRootZip,lpszFilePath	; <-- don't kill zip file ;
		.if 	eax
			; check again is ok?
			mov 	retv,eax
			jmp 	@endl
		.endif
		
		; ------- seh installation ------- ;
		SehBegin 	__dqt
		
		
		mov 	hFile,0
		invoke 	CreateFile,lpszFilePath,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
		.if 	eax != -1
			mov 	hFile,eax
			
			invoke 	GetFileSize,hFile,0
			test 	eax,eax
			jz 		@nosize
			
			mov 	fSize,eax
			
			; ------- alloc mem for pSrcMem ------- ;
			valloc 	fSize
			test 	eax,eax
			jz 		@nosize
			mov 	pSrcMem,eax
			
			invoke 	ReadFile,hFile,pSrcMem,fSize,ADDR lbrw,0
			test 	eax,eax
			jz 		@noread
			
			invoke 	CloseHandle,hFile
			
			; ------- fill header ------- ;
			lea 	esi,AnqImageHeader
			assume 	esi:ptr ANQ_IMAGE_HEADER
			
			mov 	dword ptr [esi],'FQNA'
			m2m 	[esi].lpThInfo.fSize,fSize
			lea 	eax,[esi].lpThInfo.szThreatName
			invoke 	lstrcpyn,eax,lpszThName,30
			lea 	eax,[esi].lpThInfo.szFilePath
			invoke 	lstrcpyn,eax,lpszFilePath,MAX_PATH
			mov		eax,Risk
			mov 	[esi].lpThInfo.uVirusInfo.Risk,ax
			
			; ------- alloc mem for pDstMem ------- ;
			push  	fSize
			pop 	fSize2
			add 	fSize2,sizeof ANQ_IMAGE_HEADER+2
			
			valloc 	fSize2
			test 	eax,eax
			jz 		@noread
			mov 	pDstMem,eax
			
			
			invoke 	aP_workmem_size,fSize
			
			; ------- alloc mem for pWorkingMem ------- ;
			valloc 	eax
			test 	eax,eax
			jz 		@nomem
			mov 	pWorkingMem,eax
			
			; ------- set special seh ------- ;
			SehBegin 	__appack
			
			mov 	cpack,1
			mov 	eax,pDstMem
			add 	eax,sizeof ANQ_IMAGE_HEADER+2
			lea 	edx,cbProc
			m2m 	fNewSize,fSize
			
			invoke 	aP_pack,pSrcMem,eax,fSize,pWorkingMem,edx
			mov 	fNewSize,eax
			
			SehTrap 	__appack
				; ------- action if error occured ------- ;
				invoke 	AppendLogConsole,reparg("Error during compress object")
				invoke 	AppendLogConsole,reparg("Object not compressed yet, so only store it")
				mov 	ErrOccur,1
			SehEnd		__appack	; -------  error end ;
			
			cmp 	ErrOccur,1
			je 		@OnlyStore		; ------- if error don't pack, only store it ------- ;
			
			jmp 	@packed
	@OnlyStore:	; ------- Only store ------- ;
			
			invoke 	MyZeroMemory,pDstMem,fSize2
			mov 	edx,pDstMem
			add 	edx,sizeof ANQ_IMAGE_HEADER+2
			invoke 	MyCopyMem,edx,pSrcMem,fSize
			
	@packed:
			lea 	esi,AnqImageHeader
			mov 	eax,fNewSize
			mov 	[esi].dwPackSize,eax
			
			; ------- write it header ------- ;
			invoke 	MyCopyMem,pDstMem,esi,sizeof ANQ_IMAGE_HEADER
			
			; ------- free allocated mem ------- ;
			vfree	pSrcMem
			vfree	pWorkingMem
			mov 	pSrcMem,0
			mov 	pWorkingMem,0
			
			; ------- all completed now get quarantine name index ------- ;
			xor 	edi,edi
			analloc 	MAX_PATH+1
			test 	eax,eax
			jz 		@err
			mov 	edi,eax
			
			invoke 	MyZeroMemory,ADDR lBuff,MAX_PATH
			invoke 	lstrcpy,edi,ADDR szQuarantineDir
			invoke 	TruePath,edi
			
			strlen edi
			
			mov 	len,eax
	@getit:
			inc 	nIndex
			invoke 	wsprintf,ADDR lBuff,ADDR szQfNameStyleF,nIndex
			mov 	eax,len
			mov 	byte ptr [edi+eax],0
			invoke 	lstrcat,edi,ADDR lBuff
			
			; check existing
			invoke 	FileExist,edi
			test 	eax,eax
			jnz 	@getit
			
			; ------- final file name ------- ;
			mov 	hFile,0
			invoke 	CreateFile,edi,GENERIC_WRITE,0,0,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0
			test 	eax,eax
			js		@err
			mov 	hFile,eax
			
			
			.if 	!ErrOccur	
				add 	fNewSize,sizeof ANQ_IMAGE_HEADER+2	; <-- normaly ;
			.else
				mov 	eax,fSize
				add 	eax,sizeof ANQ_IMAGE_HEADER+2	; <-- abnormal! ;
				mov 	fNewSize,eax
			.endif
			
			; ------- set index ------- ;
			mov 	ecx,nIndex
			mov 	eax,pDstMem
			mov		[eax.ANQ_IMAGE_HEADER].Index,ecx
			
			
			invoke 	WriteFile,hFile,pDstMem,fNewSize,ADDR lbrw,0
			test 	eax,eax
			jz 		@err
			
			; ------- delete old file ------- ;
			invoke 	SetFileAttributes,lpszFilePath,FILE_ATTRIBUTE_NORMAL
			invoke 	DeleteFile,lpszFilePath
			.if 	eax
				mov 	retv,1
			.else
				invoke 	CloseHandle,hFile
				mov 	hFile,0
				invoke 	DeleteFile,edi
			.endif
			
			anfree 	edi	; <-- free mem ;
			xor 	edi,edi
			
			; ------- seh trap ------- ;
			SehTrap 	__dqt
				ErrorDump 	"DoQuarantineThis",offset DoQuarantineThis,"Quarantine.asm"
			SehEnd		__dqt
			
	@err:	; ------- clean up all ------- ;
			.if 	edi
				anfree 	edi
			.endif
			.if 	pWorkingMem
				vfree 	pWorkingMem		; <-- flush mem ;
			.endif
	@nomem:
			vfree	pDstMem			; <-- flush mem ;
			assume 	esi:nothing
			
	@noread:
			.if 	pSrcMem
				vfree 	pSrcMem			; <-- flush mem ;
			.endif
	@nosize:
			.if hFile
				invoke 	CloseHandle,hFile 		; <-- close file handle ;
			.endif
		.endif
	.else
		;-------------------------------------- INSIDE ARC FILE ----------------------------------------;
		invoke 	AppendLogConsole,reparg(" Try to quarantine object inside archive file...")
		.if 	!ArcReady
			scall	ebx,reparg("archive type need module arc.dll to perform this action")
			jmp 	@endl
		.endif
		
		push 	offset szAnsavTempWorkDir	; <-- cleanup last temporary used ;
		call 	GenocideThisPath
		
		mov 	esi,lpszFilePath
		invoke	GetObjectStrArc,esi
		.if 	eax!=-1
			mov tmp,eax
			.if szObjectUnderArc[0] && szArcParent[0]
			
				invoke 	SetFileAttributes,offset szArcParent,FILE_ATTRIBUTE_NORMAL
				.if 	!tmp
					; ------- just kill it ------- ;
					; format archive path
					invoke 	ReplaceChar,offset szObjectUnderArc,'\','/',MAX_PATH
					
					push 	offset 	szObjectUnderArc
					push 	offset 	szArcParent
					call 	[ZII.KillZipItem]
					add 	esp,4*2
					RevEax
					mov 	retv,eax
				.else
					lea 	esi,lBuff
					invoke 	MyZeroMemory,esi,MAX_PATH
					
					push 	offset szArcWayToTarget
					push 	offset szArcParent
					call 	[ZII.KillSubSubItem]	; <-- sub sub kill ;
					add 	esp,4*2
					mov 	retv,eax
					
				.endif
			.endif
		.endif
	.endif	
	
@endl:	
	mov 	eax,retv
	ret

DoQuarantineThis endp

Align 16

DoActionThisFQ proc uses edi esi ebx FQAction:DWORD

	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	LOCAL 	szThName[30]:BYTE
	LOCAL 	szOldLocation[MAX_PATH+1]:BYTE
	LOCAL 	wfd:WIN32_FIND_DATA
	LOCAL 	hFind:DWORD
	LOCAL 	len,found,iIndex:DWORD
	LOCAL 	Anqih:ANQ_IMAGE_HEADER
	LOCAL 	lvi:LV_ITEM
	
	; ------- seh installation ------- ;
	SehBegin 	__datfq
	
	mov 	edi,MyZeroMemory
	
	lea 	eax,lBuff
	scall 	edi,eax,MAX_PATH
	lea 	eax,szOldLocation
	scall 	edi,eax,MAX_PATH
	lea 	eax,szThName
	scall 	edi,eax,30
	lea 	eax,wfd
	scall 	edi,eax,sizeof WIN32_FIND_DATA
	lea 	eax,Anqih
	scall 	edi,eax,sizeof ANQ_IMAGE_HEADER
	lea 	eax,lvi
	scall 	edi,eax,sizeof LV_ITEM

	mov 	edi,SendMessage
	mov 	esi,hListQuarantine
	
	mov 	[lvi.imask],LVIF_TEXT
	mov 	[lvi.cchTextMax],MAX_PATH
	scall 	edi,esi,LVM_GETNEXTITEM,-1,LVNI_SELECTED
	mov 	[lvi.iItem],eax
	mov 	iIndex,eax
	lea 	eax,szThName
	mov 	[lvi.pszText],eax
	lea 	eax,lvi
	scall 	edi,esi,LVM_GETITEM,0,eax
	lea 	eax,szOldLocation
	mov 	[lvi.pszText],eax
	inc 	[lvi.iSubItem]
	lea 	eax,lvi
	scall 	edi,esi,LVM_GETITEM,0,eax
	
	cmp 	szThName[0],0
	jne 	@F
		SehPop
		ret
	@@:
	cmp 	szOldLocation[0],0
	jne 	@F
		SehPop
		ret
	@@:
	
	mov 	ebx,AppendLogConsole
	
	; ------- confirm ------- ;
	analloc		256
	.if 	eax
		mov 	esi,eax
		.data
			szConfirmAFQF	db "Are you sure to %s this threat: %s",13,10
							db "that have old location in %s ?",0
			szRestore		db "restore",0
		.code
		
		mov 	eax,FQAction
		.if 	eax == FQ_ACTION_DELETE
			mov 	edx,reparg("delete")
		.elseif 	eax== FQ_ACTION_RESTORE
			lea 	edx,szRestore
		.elseif 	eax == FQ_ACTION_RESTOREAS
			lea 	edx,szRestore
		.endif
		invoke 	wsprintf,esi,ADDR szConfirmAFQF,edx,ADDR szThName,ADDR szOldLocation
		invoke 	MessageBox,hQuarantineDlg,esi,ADDR szAppName,MB_ICONQUESTION or MB_OKCANCEL
		.if 	eax != IDOK
			anfree 	esi
			SehPop
			ret
		.endif
		
		anfree 	esi
	.endif
	
	call 	InitQuarantine
	.if 	eax
		lea 	edi,lBuff
		invoke 	lstrcpy,edi,ADDR szQuarantineDir
		invoke 	TruePath,edi
		
		strlen edi
		
		mov 	len,eax
		mov 	byte ptr [edi+eax],'*'
		
		align 4
		mov 	found,0
		
		invoke 	FindFirstFile,edi,ADDR wfd
		.if 	eax!=-1 && eax!=0
			mov 	hFind,eax
			.while 	eax
				
				mov 	ecx,len
				mov 	byte ptr [edi+ecx],0
				lea 	eax,wfd.cFileName
				invoke 	lstrcat,edi,eax
				
				; ------- is file ------- ;
				invoke 	GetFileAttributes,edi
				.if 	!(ax & FILE_ATTRIBUTE_DIRECTORY)	
					invoke	GetFQInfo,ADDR Anqih,edi
					.if 	eax
						lea 	eax,[Anqih.lpThInfo.szThreatName]
						invoke 	lstrcmpi,ADDR szThName,eax
						jne 	@nx
						lea 	eax,[Anqih.lpThInfo.szFilePath]
						invoke 	lstrcmpi,ADDR szOldLocation,eax
						jne 	@nx
						; ------- ; ------- ; ------- ; ------- ; ------- PROCESSING ------- ; ------- ; ------- ; ------- ; ------- ;
							mov 	eax,FQAction
							.if 	eax==FQ_ACTION_RESTORE
								; ------- TRY TO RESTORE ------- ;
								inc 	found
								; ------- restore this ANQ ------- ;
								invoke 	RestoreFQ,edi,0
								.if 	!eax
									scall ebx,offset szThisFile
									scall ebx,edi
									scall ebx,reparg(" - Cannot restore quarantine object")
								.else
									; ------- delete file FQ ------- ;
									invoke 	SetFileAttributes,edi,FILE_ATTRIBUTE_NORMAL
									invoke 	Sleep,5
									invoke 	DeleteFile,edi
									.if 	eax
										invoke 	SendMessage,hListQuarantine,LVM_DELETEITEM,iIndex,0
									.else
										scall ebx,reparg("- Cannot delete quarantine file object, delete it manuali in quarantine directory") 
									.endif
								.endif
								jmp 	@sudas
							.elseif eax == FQ_ACTION_RESTOREAS	; ------- TRY TO RESTORE AS ------- ;
								; ------- restore this ANQ ------- ;
								inc 	found
								invoke 	RestoreFQ,edi,1
								.if 	!eax
									scall ebx,offset szThisFile
									scall ebx,edi
									scall ebx,reparg(" - Cannot restore quarantine object")
								.else
									; ------- delete file FQ ------- ;
									invoke 	SetFileAttributes,edi,FILE_ATTRIBUTE_NORMAL
									invoke 	Sleep,5
									invoke 	DeleteFile,edi
									.if 	eax
										invoke 	SendMessage,hListQuarantine,LVM_DELETEITEM,iIndex,0
									.else
										scall ebx,reparg("- Cannot delete quarantine file object, delete it manuali in quarantine directory") 
									.endif
								.endif
								jmp 	@sudas
							.elseif eax == FQ_ACTION_DELETE		; ------- DELETE ------- ;
								inc 	found
								; ------- delete this ANQ ------- ;
								invoke 	KillObjectForcely,edi
								.if 	!eax
									scall ebx,offset szThisFile
									scall ebx,edi
									scall ebx,reparg(" - Cannot delete quarantine object")
								.else
									invoke 	SendMessage,hListQuarantine,LVM_DELETEITEM,iIndex,0
								.endif
								jmp 	@sudas
							.elseif	eax == FQ_ACTION_DELETEALL	; ------- DELETE ALL ------- ;
								inc 	found
								invoke 	SetFileAttributes,edi,FILE_ATTRIBUTE_NORMAL
								invoke 	Sleep,30
								invoke 	DeleteFile,edi
								.if 	!eax
									scall ebx,offset szThisFile
									scall ebx,edi
									scall ebx,reparg(" - Cannot delete quarantine object")
								.else
									invoke 	SendMessage,hListQuarantine,LVM_DELETEITEM,iIndex,0
								.endif
							.endif	; FQ_ACTION
					.endif ; GetFQInfo
				.endif ; GetFileAttributes
				@nx:
				invoke 	FindNextFile,hFind,ADDR wfd
			.endw 
@sudas:	; --------------> ;
			invoke 	FindClose,hFind
		.endif
		
	.endif
	
	; ------- seh trap ------- ;
	SehTrap		__datfq
		ErrorDump	"DoActionThisFQ",offset DoActionThisFQ,"Quarantine.asm"
	SehEnd		__datfq
	ret

DoActionThisFQ endp

Align 16

cbProc proc C len1:DWORD,len2:DWORD

    mov eax, cpack
    ret

cbProc endp

Align 16

; ------- restore quarantine object ------- ;
RestoreFQ proc uses esi edi ebx	lpszFile:DWORD, lpAS:DWORD
	
	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	LOCAL 	lBuff2[MAX_PATH+1]:BYTE
	LOCAL 	hFile,fSize:DWORD
	LOCAL 	pSrcMem,pDstMem:DWORD
	LOCAL 	PackedSize,UnpackedSize:DWORD
	LOCAL 	of:OPENFILENAME
	LOCAL 	retv:DWORD
	LOCAL 	lbrw:DWORD
	
	; ------- seh installation ------- ;
	SehBegin 	__rfq

	invoke 	MyZeroMemory,ADDR lBuff,MAX_PATH
	invoke 	MyZeroMemory,ADDR lBuff2,MAX_PATH
	invoke 	MyZeroMemory,ADDR of,sizeof OPENFILENAME
	
	mov 	PackedSize,0
	mov 	retv,0
	
	
	invoke 	CreateFile,lpszFile,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
	.if 	eax != -1
		mov 	hFile,eax
		invoke 	GetFileSize,eax,0 
		.if 	eax
			mov 	fSize,eax
			valloc 	eax
			.if 	eax
				mov 	pSrcMem,eax
				
				invoke 	ReadFile,hFile,pSrcMem,fSize,ADDR lbrw,0
				test 	eax,eax
				jz 		@nx
				
				mov 	esi,pSrcMem
				assume 	esi:ptr ANQ_IMAGE_HEADER
				
				.if 	!lpAS
					; ------- check for old location to be exist ------- ;
					
					lea 	eax,[esi].lpThInfo.szFilePath
					cmp 	byte ptr [eax],0
					je		@nx
					lea 	ebx,lBuff
					invoke 	lstrcpy,ebx,eax
					invoke 	OnlyPathDir,ebx
					
					
					invoke 	GetFileAttributes,ebx
					test 	eax,FILE_ATTRIBUTE_DIRECTORY
					.if 	zero?
						invoke 	AppendLogConsole,ADDR szThisPath
						invoke 	AppendLogConsole,ebx
						invoke 	AppendLogConsole,reparg(" - not found or not accessible")
						invoke 	MessageBox,hQuarantineDlg,ADDR szOLnotEx,ADDR szAppName,MB_YESNO
						cmp 	eax,IDNO
						je 		@nx
							mov 	lpAS,1	; <-- set to save as ; 
					.endif
					
				.endif
				
				; ------- check is packed? ------- ;
				mov 	eax,[esi].dwPackSize
				mov 	ecx,[esi].lpThInfo.fSize
				mov 	UnpackedSize,ecx
				cmp 	UnpackedSize,eax
				je		@F
					mov 	PackedSize,eax
				@@:
				
				.if 	PackedSize
					; ------- if packed, extract it first ------- ;
					
					valloc 	UnpackedSize
					.if 	eax
						mov 	pDstMem,eax
						
						mov 	eax,pSrcMem
						add 	eax,sizeof ANQ_IMAGE_HEADER+2
						
						; ------- unpack ------- ;
						invoke 	aP_depack_asm_fast,eax,pDstMem
						
						; ------- save it ------- ;
						.if 	!lpAS
							lea	edi,[esi].lpThInfo.szFilePath
@saveitp:; --------------> ;
							; ------- save to old location ------- ;
							invoke	CreateFile,edi,GENERIC_WRITE,FILE_SHARE_WRITE,0,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0
							push 	eax
								call 	GetLastError
								.if 	eax == ERROR_ALREADY_EXISTS
									invoke 	AppendLogConsole,reparg("Cannot create output file to restore quarantine object, ERROR : File already exist")
									call 	CloseHandle
									jmp 	@nx2
								.endif
							pop 	eax
							.if 	eax!=-1
								; ------- save ------- ;
								
								push 	eax
								lea 	edx,lbrw
								invoke 	WriteFile,eax,pDstMem,UnpackedSize,edx,0
								call 	CloseHandle
							.else
								invoke 	AppendLogConsole,reparg("Cannot create file output to restore quarantine object")
							.endif
						@nx2:
						.else
							; ------- save as user defined for location ------- ;
							
							mov 	[of.lStructSize],sizeof OPENFILENAME
							m2m 	[of.hwndOwner],hQuarantineDlg
							m2m 	[of.hInstance],hInstance
							mov 	[of.lpstrFilter],offset szMaskAllFile
							lea 	eax,[esi].lpThInfo.szFilePath
							invoke 	OnlyFileName,ADDR lBuff,eax
							lea 	eax,lBuff
							mov 	[of.lpstrFileTitle],eax
							mov 	[of.nMaxFileTitle],MAX_PATH
							lea 	edi,lBuff2
							mov 	[of.lpstrFile],edi
							mov 	[of.nMaxFile],MAX_PATH
							mov 	[of.lpstrTitle],reparg("Restore As...")
							invoke 	GetSaveFileName,ADDR of 
							.if 	byte ptr [edi]
								
								jmp 	@saveitp
								
							.endif
						.endif
						
						vfree 	pDstMem
					.endif
				.else
					; ------- if not packed object ------- ;
					.if 	!lpAS
						lea	edi,[esi].lpThInfo.szFilePath
@saveitnp:; --------------> ;
						; ------- save to old location ------- ;
						invoke	CreateFile,edi,GENERIC_WRITE,FILE_SHARE_WRITE,0,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0
						
						push 	eax
							call 	GetLastError
							.if 	eax == ERROR_ALREADY_EXISTS
								invoke 	AppendLogConsole,reparg("Cannot create output file to restore quarantine object, ERROR : File already exist")
								call 	CloseHandle
								jmp 	@nx2
							.endif
						pop 	eax
						
						.if 	eax!=-1
							; ------- save ------- ;
							
							push 	eax
							mov 	edx,pSrcMem
							add 	edx,sizeof ANQ_IMAGE_HEADER+2
							lea 	ecx,lbrw
							invoke 	WriteFile,eax,edx,UnpackedSize,ecx,0
							call 	CloseHandle
						.else
							invoke 	AppendLogConsole,reparg("Cannot create file output to restore quarantine object")
						.endif
					.else
						; ------- save as user defined for location ------- ;
						
						mov 	[of.lStructSize],sizeof OPENFILENAME
						m2m 	[of.hwndOwner],hQuarantineDlg
						m2m 	[of.hInstance],hInstance
						mov 	[of.lpstrFilter],offset szMaskAllFile
						lea 	eax,[esi].lpThInfo.szFilePath
						invoke 	OnlyFileName,ADDR lBuff,eax
						lea 	eax,lBuff
						mov 	[of.lpstrFileTitle],eax
						mov 	[of.nMaxFileTitle],MAX_PATH
						lea 	edi,lBuff2
						mov 	[of.lpstrFile],edi
						mov 	[of.nMaxFile],MAX_PATH
						mov 	[of.lpstrTitle],reparg("Restore As...")
						invoke 	GetSaveFileName,ADDR of 
						.if 	byte ptr [edi]
							
							jmp 	@saveitnp
							
						.endif
					.endif
					
				.endif
				
				assume 	esi:nothing
				
				@nx:
				vfree	pSrcMem
			.endif
			
		.endif
		
		invoke 	CloseHandle,hFile
	.endif
	
	; ------- seh trap ------- ;
	SehTrap 	__rfq
		ErrorDump	"RestoreFQ",offset RestoreFQ,"Quarantine"
	SehEnd		__rfq
	
	ret

RestoreFQ endp

Align 16

; ------- get file quarantine info ------- ;
GetFQInfo proc uses esi edi lpANQIH:DWORD, lpszFile:DWORD
	
	LOCAL 	hFile,fSize,pMem:DWORD
	LOCAL 	retv:DWORD
	
	; ------- seh installation ------- ;
	SehBegin 	__gfqi
	
	mov 	retv,0
	
	invoke 	CreateFile,lpszFile,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
	.if 	eax != -1
		mov 	hFile,eax
		
		invoke 	GetFileSize,hFile,0
		.if 	eax
			mov 	fSize,eax
			
			cmp 	eax,sizeof ANQ_IMAGE_HEADER
			jb 		@nosize
			
			; ------- alloc mem ------- ;
			valloc 	eax
			.if 	eax
				mov 	pMem,eax
				
				invoke 	ReadFile,hFile,pMem,sizeof ANQ_IMAGE_HEADER,ADDR brw,0
				
				; ------- check for valid ANQ format header ------- ;
				mov 	esi,pMem
				assume 	esi:ptr ANQ_IMAGE_HEADER
				
				cmp 	dword ptr [esi],'FQNA'
				jne 	@novanqh
				
				mov 	eax,[esi].dwPackSize
				
				mov 	edi,lpANQIH
				assume 	edi:ptr ANQ_IMAGE_HEADER
				
				mov 	[edi].dwPackSize,eax	; <-- pack size ;
				
				mov 	eax,[esi].lpThInfo.fSize
				test 	eax,eax
				jz 		@novanqh
				mov 	[edi].lpThInfo.fSize, eax	; <-- real size ;
				
				lea 	eax,[esi].lpThInfo.szFilePath
				cmp 	byte ptr [eax],0
				je 		@novanqh
				
				lea 	edx,[edi].lpThInfo.szFilePath	; <-- path ;
				invoke 	lstrcpyn,edx,eax,MAX_PATH
				
				mov 	ax,[esi].lpThInfo.uVirusInfo.Risk
				mov 	[edi].lpThInfo.uVirusInfo.Risk,ax	; <-- risk ;
				
				lea 	eax,[esi].lpThInfo.szThreatName
				lea 	edx,[edi].lpThInfo.szThreatName
				invoke 	lstrcpyn,edx,eax,30
				
				mov 	eax,[esi].Index
				mov 	[edi].Index,eax
				
				mov 	retv,1 	; <-- set return value ;
				
				assume 	esi:nothing
				assume 	edi:nothing
			@novanqh:
				
				; ------- flush mem ------- ;
				vfree 	pMem
			.endif
			@nosize:
		.endif
		
		invoke 	CloseHandle,hFile
	.endif
	
	; ------- seh trap ------- ;
	SehTrap 	__gfqi
		ErrorDump 	"GetFQInfo",offset GetFQInfo,"Quarantine"
	SehEnd		__gfqi
	
	mov 	eax,retv
	ret

GetFQInfo endp


Align 16


InitQuarantine proc
	
	LOCAL 	retv:DWORD
	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	
	
	SehBegin 	__iq
	
	mov 	retv,0
	
	invoke 	GetFileAttributes,ADDR szQuarantineDir
	call 	GetLastError
	.if 	eax == ERROR_FILE_NOT_FOUND
		
		invoke 	AppendLogConsole,reparg("Quarantine directory not found, try to build it first...")
		; make it
		invoke 	CreateDirectory,ADDR szQuarantineDir,0
		.if 	eax
			invoke 	AppendLogConsole,ADDR szSuccess
			mov 	retv,1
		.else
			invoke 	AppendLogConsole,ADDR szFailed
		.endif
	.else
		; ------- check for accessible ------- ;
		invoke	MyZeroMemory,ADDR lBuff,MAX_PATH
		invoke 	lstrcpy,ADDR lBuff,ADDR szQuarantineDir
		invoke	TruePath,ADDR lBuff
		invoke 	lstrcat,ADDR lBuff,ADDR szBrw
		
		invoke 	CreateFile,ADDR lBuff,GENERIC_WRITE,FILE_SHARE_WRITE,0,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0
		push 	eax
		call 	GetLastError
		.if 	eax == ERROR_FILE_EXISTS
			add 	esp,4
			; delete it
			invoke 	DeleteFile,ADDR lBuff
			.if 	!eax
				invoke 	AppendLogConsole,reparg("Quarantine directory not accessible, or not writable")
			.else
				mov 	retv,1
			.endif
		.else
			call 	CloseHandle
			; suckses, delete it
			invoke 	DeleteFile,ADDR lBuff
			.if 	eax
				mov 	retv,1
			.endif
			 
		.endif
	.endif
	
	
	SehTrap 	__iq
		ErrorDump 	"InitQuarantine",offset InitQuarantine,"Quarantine.asm"
	SehEnd 		__iq
	
	
	mov 	eax,retv
	ret

InitQuarantine endp

Align 16

DeleteQuarantineAll proc

	LOCAL 	wfd:WIN32_FIND_DATA
	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	LOCAL 	hFind,len:DWORD
	
	SehBegin 	__dqa
	
	
	lea 	edi,lBuff
	invoke 	MyZeroMemory,ADDR wfd,sizeof WIN32_FIND_DATA
	invoke 	MyZeroMemory,edi,MAX_PATH
	
	invoke 	SendMessage,hListQuarantine,LVM_DELETEALLITEMS,0,0
	
	invoke 	lstrcpy,edi,ADDR szQuarantineDir
	invoke 	TruePath,edi
	
	strlen edi
	
	mov 	len,eax
	mov 	byte ptr [edi+eax],'*'
	
	invoke 	FindFirstFile,edi,ADDR wfd
	.if 	eax!= -1 && eax!=0
		mov 	hFind,eax
		.while eax
			lea 	eax,wfd.cFileName
			.if 	byte ptr [eax]!='.'
				mov 	eax,len
				mov 	byte ptr [edi+eax],0
				lea 	eax,wfd.cFileName
				invoke 	lstrcat,edi,eax
				
				invoke 	SetFileAttributes,edi,FILE_ATTRIBUTE_NORMAL
				invoke 	DeleteFile,edi
			.endif
			invoke 	FindNextFile,hFind,ADDR wfd
		.endw
		invoke 	FindClose,hFind
	.endif
	
	call 	GetAllFQInfo
	
	invoke 	SendMessage,hListQuarantine,LVM_GETITEMCOUNT,0,0

	SehTrap 	__dqa
		ErrorDump	"DeleteQuarantineAll",offset DeleteQuarantineAll,"Quarantine.asm"
	SehEnd 		__dqa

	ret
DeleteQuarantineAll endp

