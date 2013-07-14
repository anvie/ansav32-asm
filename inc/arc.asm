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


;-------------------------------------- arc.asm ----------------------------------------;
IsRootZip 	PROTO :DWORD

.data?
	_ZII struct
		ExtractAllTo DWORD ?
		KillZipItem DWORD ?
		AnzipGetLastError DWORD ?
		BuildDirectory DWORD ?
		ExtractJustOneItem DWORD ?
		KillSubSubItem DWORD ?
	_ZII ends
	ZII _ZII <>
	hArcMod dd ?
	ArcReady dd ?
	InsideZip dd ?
	ZipFileName dd ?
	RootZipFileName dd ?
	NumThreatInsideArc dd ?
	SubArchive dd ?	
.code

align 16

ArcInit proc 

	; ------- seh installation ------- ;
	SehBegin 	_ai

	invoke 	LoadLibrary,offset szArcdll
	.if 	eax
		mov 	hArcMod,eax
		invoke 	GetProcAddress,eax,reparg("Initialize")
		.if 	eax
			lea 	edx,ZII
			push 	edx
			push 	edx
			call 	eax
			add 	esp,4h
			pop 	edx
			.if 	[edx._ZII].ExtractAllTo && \
					[edx._ZII].KillZipItem && \
					[edx._ZII].AnzipGetLastError && \
					[edx._ZII].BuildDirectory && \
					[edx._ZII].ExtractJustOneItem && \
					[edx._ZII].KillSubSubItem
				SehPop
				return_1
			.endif
		.endif
	.endif
	
	; ------- seh trapper ------- ;
	SehTrap 	_ai
		ErrorDump 	"ArcInit",offset ArcInit,"arc.asm"
	SehEnd 		_ai
	
	return_0

ArcInit endp

align 16

IsObjectInsideArc? proc uses ebx edi lpszObject:DWORD
	
	LOCAL 	tmp:DWORD
	LOCAL 	retv:DWORD
	
	; ------- seh installation ------- ;
	SehBegin 	__ioia
	
	mov 	tmp,0
	mov 	retv,0
	
	mov 	edi,lpszObject
	xor 	ebx,ebx
	
	strlen edi
	
	mov 	ecx,eax
	mov 	tmp,eax
	@lp:
		cmp 	byte ptr [edi+ecx],':'
		.if 	zero?
			inc 	ebx
		.endif
	loop 	@lp
	.if 	ebx<2
		SehPop
		return_0
	.endif
	push 	edi
		cld
		mov 	al,':'
		mov 	ecx,tmp
		repne 	scasb
		repne	scasb
		cmp 	byte ptr [edi],0
		.if 	zero?
			add 	esp,4
			SehPop
			return_0
		.else
			dec 	edi
			mov 	tmp,edi
		.endif
	pop 	edi
	.if 	ebx>1
		
		; ------- check for valid zip file ------- ;
		mov 	eax,tmp
		mov 	byte ptr [eax],0
		invoke 	IsRootZip,edi
		.if 	eax
			mov 	retv,1
		.endif
		mov 	eax,tmp
		mov 	byte ptr [eax],':'
	.endif
	
	; ------- seh trapper ------- ;
	SehTrap 	__ioia
		ErrorDump 	"IsObjectInsideArc?",offset IsObjectInsideArc?,"arc.asm"
	SehEnd 		__ioia
	
	mov 	eax,retv
	ret

IsObjectInsideArc? endp

align 16

IsItemInsideArc proc uses edi esi lItem:DWORD
	
	LOCAL lvi:LV_ITEM
	LOCAL lbuff[MAX_PATH+1]:BYTE
	
	; ------- seh installation ------- ;
	SehBegin	__iiia
	
	lea 	esi,lvi
	lea 	edi,lbuff
	invoke 	MyZeroMemory,esi,sizeof LV_ITEM
	invoke 	MyZeroMemory,edi,MAX_PATH
	
	mov 	[lvi.imask],LVIF_TEXT
	mov2 	[lvi.iItem],lItem
	mov 	[lvi.iSubItem],1
	mov 	[lvi.pszText],edi
	mov 	[lvi.cchTextMax],MAX_PATH
	invoke 	SendMessage,hMainList,LVM_GETITEM,0,esi
	
	.if 	byte ptr [edi]
		mov 	ecx,MAX_PATH
		cld
		mov 	al,':'
		repne 	scasb
		repne 	scasb
		.if 	zero?
			SehPop
			return_1
		.endif
	.endif
	
	; ------- seh trapper ------- ;
	SehTrap 	__iiia
		ErrorDump	"IsItemInsideArc",offset IsItemInsideArc,"arc.asm"
	SehEnd 		__iiia
	
	return_0
	
	ret

IsItemInsideArc endp

align 16

.data?
	szArcParent db MAX_PATH+1 dup(?)
	szObjectUnderArc db MAX_PATH+1 dup(?)
	szArcWayToTarget db (MAX_PATH*4)+1 dup (?)
.code

GetObjectStrArc proc uses edi esi ebx lpZipObject:DWORD

	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	LOCAL 	tmp,retv:DWORD
	
	
	; ------- seh installation ------- ;
	SehBegin 	__gosa
	
	mov 	esi,MyZeroMemory
	
	scall 	esi,offset szObjectUnderArc,MAX_PATH
	scall 	esi,offset szArcParent,MAX_PATH
	lea 	eax,lBuff
	scall 	esi,eax,MAX_PATH
	
	mov 	tmp,0
	mov 	retv,-1
	
	; ------- get parent arc ------- ;
	mov 	edi,lpZipObject
	push 	edi
		strlen edi
		
		mov 	ecx,eax
		cld
		mov 	al,':'
		repne 	scasb
		repne 	scasb
		.if 	byte ptr [edi]
			dec 	edi
			mov 	byte ptr [edi],0
			mov 	tmp,edi
		.else
			add	esp,4
			SehPop
			return_0
		.endif
	pop 	edi
	
	invoke 	lstrcpyn,offset szArcParent,edi,MAX_PATH
	
	mov 	eax,tmp
	mov 	byte ptr [eax],':'
	
	; ------- get inside object ------- ;
	add 	tmp,2
	
	; get way num
	EndString 	MAX_PATH
	dec edi
	xor ecx,ecx
	@@:
		cmp byte ptr [edi],']'
		.if 	zero?
			inc 	ecx
		.else
			jmp @F
		.endif
		dec 	edi
		jmp @B
	@@:
	push ecx
		lea esi,szArcWayToTarget
		invoke 	MyZeroMemory,esi,MAX_PATH*4
		
		lea 	edi,lBuff
		invoke 	lstrcpyn,edi,tmp,MAX_PATH
	pop tmp
	xor ebx,ebx
	invoke 	ReplaceChar,edi,':',0,MAX_PATH
	
	@lp:; ------- BUILD WAY ------- ;
		push edi
			xchg edi,esi
			
			strlen esi
			
			mov ecx,eax
			cld
			.if edi!=offset szArcWayToTarget
				inc edi
			.endif
			.if byte ptr [esi]=='['
				inc esi
				dec ecx
			.endif
			rep movsb
			inc retv
			inc ebx
			.if ebx==tmp
				mov ecx,tmp
				sub edi,ecx
				mov al,0
				cld
				rep stosb
				push 	edi
				sub 	edi,tmp
				dec 	edi
				@@:
					cmp 	byte ptr [edi],0
					je 		@F
					dec 	edi
					jmp 	@B
				@@:
				inc 	edi
				invoke 	lstrcpyn,offset szObjectUnderArc,edi,MAX_PATH
				pop 	edi
			.endif
			xchg edi,esi
		pop edi
	NextArray @lp
	
	; ------- seh trapper ------- ;
	SehTrap 	__gosa
		ErrorDump 	"GetObjectStrArc",offset GetObjectStrArc,"arc.asm"
	SehEnd 		__gosa
	
	mov 	eax,retv
	
	ret

GetObjectStrArc endp

align 16

PrepareExtractionWay proc uses edi lpszBuffer:DWORD, lpPath:DWORD

	LOCAL 	lBuff[MAX_PATH]:BYTE
	
	; ------- seh installation ------- ;
	SehBegin 	__pew
	
	lea 	edi,lBuff
	.if 	!byte ptr [edi]
		SehPop
		return_0
	.endif
	invoke 	MyZeroMemory,edi,MAX_PATH
	invoke 	lstrcpyn,edi,offset szAnsavTempWorkDir,MAX_PATH
	invoke 	TruePath,edi
	push 	edi
		cld
		xor al,al
		mov ecx,MAX_PATH
		repne scasb
		invoke 	OnlyFileName,edi,lpPath
	pop 	edi
	push 	edi
	call 	[ZII.BuildDirectory]
	add 	esp,4	; <-- fix stack ;
	
	invoke 	lstrcpyn,lpszBuffer,eax,MAX_PATH
	
	; ------- seh trapper ------- ;
	SehTrap 	__pew
		ErrorDump 	"PrepareExtractionWay",offset PrepareExtractionWay,"arc.asm"
	SehEnd 		__pew
	
	mov 	eax,lpszBuffer
	ret

PrepareExtractionWay endp

align 16



