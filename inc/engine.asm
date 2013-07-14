;------------------------------------------------------------------------------;
;
;   ANSAV An's Antivirus
;   Copyright (C) 2007-2008 Muqorrobien Ma'rufi a.k.a 4NV|e
;
;   This program is free software; you can redistribute it and/or modify
;   it under the terms of the GNU General Public License as published by
;   the Free Software Foundation; either version 2 of the License, or 
;   (at your option) any later version.
;
;   This program is distributed in the hope that it will be usefull,
;   but WITHOUT ANY WARRANTY; without even the implied warranty of
;   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
;   General Public License for more details.
;
;   You should have received a copy of the GNU General Public License
;   along with this program; if not, write to the Free Software 
;   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
;   MA 02110-1301, USA.
;   
;   Muqorrobien Ma'rufi a.k.a 4NV|e
;   anvie_2194 @ yahoo.com
;   http://www.ansav.com
;   PP. Miftahul Huda Blok C Siwatu Wonosobo 56352 Jawa Tengah Indonesia
;   
;
;------------------------------------------------------------------------------;


; ------- engine.asm  ------- ;
; main module for ansav
.data

	IMAGE_SECTION_WRITEABLE 	equ 	080000000h
	IMAGE_SECTION_READABLE		equ 	040000000h
	IMAGE_SECTION_EXECUTABLE 	equ 	020000000h
	IMAGE_SECTION_SHARED		equ 	010000000h
	IMAGE_SECTION_DATA 			equ 	040h

	szEngineAsm db "engine.asm",0
.code

align 16

; ------- file scanning initial first ------- ;
InitLoadScannableFile proc
	
	; ------- Null it all global flag to scan file ------- ;
	lea 	eax,ScannableFileObject
	assume 	eax:ptr WORKFILE
	mov 	[eax].lpVoidMem,0
	mov 	[eax].fMap,0
	mov		[eax].fSize,0
	mov 	[eax].hFile,0
	assume 	eax:nothing
	
	ret

InitLoadScannableFile endp

align 16

; ------- load work file to scan ------- ;
; s. return value = 1
; f. return value = 0
LoadScanableFile proc uses esi lpszFile:DWORD
    LOCAL 	lbrw:DWORD
    LOCAL   hFile,fSize,memptr:DWORD
    LOCAL   fMap:DWORD
    LOCAL 	arcfile,retv:DWORD
    LOCAL 	lBuff[10]:BYTE
    
    closef MACRO 
    	push 	hFile
    	call 	CloseHandle
    endm
    
    align 4
    ; ------- seh installation ------- ;
    SehBegin	__lsf
    
    
    mov 	arcfile,0
    mov 	retv,0
    
    call 	CloseScanableFile
    
    ; ------- Init first ------- ;
    call 	InitLoadScannableFile
    
    mov 	hFile,0
    mov 	fMap,0
    mov 	memptr,0
    
    ; ------- Open file ------- ;
	invoke  CreateFile,lpszFile,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,0,0
	.if     eax != -1
		mov     hFile,eax
		
		align 4
		
		; ------- Get it size ------- ;
		invoke  GetFileSize,hFile,0
		mov 	fSize,eax
		
		.if 	!fSize
			.if 	!InsideZip
				jmp 	@nosize
			.else
				invoke 	AppendLogConsole,reparg("null size, may password needed to extract this file? :")
				invoke 	AppendLogConsole,lpszFile
			.endif
		.endif
		
		align 4
		lea 	esi,lBuff
		invoke 	MyZeroMemory,esi,9
		
			invoke 	ReadFile,hFile,esi,4,ADDR lbrw,0
			
			cmp 	word ptr [esi],0FBFFh	; MP3
			.if 	zero?
				mov 	[ScannableFileObject.FileType],FILE_TYPE_EXCLUDE
				closef
				SehPop
				return_0
			.endif
			cmp 	word ptr [esi],0FAFFh	; MP3
			.if 	zero?
				mov 	[ScannableFileObject.FileType],FILE_TYPE_EXCLUDE
				closef
				SehPop
				return_0
			.endif
			cmp 	word ptr [esi],04449h	; MP3
			.if 	zero?
				mov 	[ScannableFileObject.FileType],FILE_TYPE_EXCLUDE
				closef
				SehPop
				return_0
			.endif
			cmp 	dword ptr [esi],075B22630h ; WMA
			.if 	zero?
				mov 	[ScannableFileObject.FileType],FILE_TYPE_EXCLUDE
				closef
				SehPop
				return_0
			.endif
			cmp 	dword ptr [esi],046464952h ; AVI
			.if 	zero?
				mov 	[ScannableFileObject.FileType],FILE_TYPE_EXCLUDE
				closef
				SehPop
				return_0
			.endif
			cmp 	dword ptr [esi],0E011CFD0h ; THUMB
			.if 	zero?
				mov 	[ScannableFileObject.FileType],FILE_TYPE_EXCLUDE
				closef
				SehPop
				return_0
			.endif
			;42 4D 76 02
			cmp 	dword ptr [esi],002764D42h ; BMP
			.if 	zero?
				mov 	[ScannableFileObject.FileType],FILE_TYPE_EXCLUDE
				closef
				SehPop
				return_0
			.endif
			;89 50 4E 47
			cmp 	dword ptr [esi],0474E5089h ; PNG
			.if 	zero?
				mov 	[ScannableFileObject.FileType],FILE_TYPE_EXCLUDE
				closef
				SehPop
				return_0
			.endif
			;FF D8 FF E0
			cmp 	dword ptr [esi],0E0FFD8FFh ; JPG
			.if 	zero?
				mov 	[ScannableFileObject.FileType],FILE_TYPE_EXCLUDE
				closef
				SehPop
				return_0
			.endif
			cmp 	dword ptr [esi],0E1FFD8FFh ; JPG
			.if 	zero?
				mov 	[ScannableFileObject.FileType],FILE_TYPE_EXCLUDE
				closef
				SehPop
				return_0
			.endif
			;00 01 01 00
			cmp 	dword ptr [esi],000010100h ; TGA
			.if 	zero?
				mov 	[ScannableFileObject.FileType],FILE_TYPE_EXCLUDE
				closef
				SehPop
				return_0
			.endif
			;47 49 46 38
			cmp 	dword ptr [esi],038464947h ; GIF
			.if 	zero?
				mov 	[ScannableFileObject.FileType],FILE_TYPE_EXCLUDE
				closef
				SehPop
				return_0
			.endif
			;25 50 44 46
			cmp 	dword ptr [esi],046445025h ; PDF
			.if 	zero?
				mov 	[ScannableFileObject.FileType],FILE_TYPE_EXCLUDE
				closef
				SehPop
				return_0
			.endif
			;66 74 79 70
			align 4
			cmp 	dword ptr [esi+4],070797466h ; 3gp
			.if 	zero?
				mov 	[ScannableFileObject.FileType],FILE_TYPE_EXCLUDE
				;anfree 	esi
				closef
				SehPop
				return_0
			.endif
			; 01 01 02 00
			align 4
			cmp 	dword ptr [esi],000020101h ; PNF
			.if 	zero?
				mov 	[ScannableFileObject.FileType],FILE_TYPE_EXCLUDE
				closef
				SehPop
				return_0
			.endif
			; 00 01 00 00
			align 4
			cmp 	dword ptr [esi],000000100h ; TTF
			.if 	zero?
				mov 	[ScannableFileObject.FileType],FILE_TYPE_EXCLUDE
				closef
				SehPop
				return_0
			.endif
			
			; PK
			align 4
			cmp 	word ptr [esi],'KP' ; ZIP
			.if 	zero?
				mov 	arcfile,1
			.endif
			
			align 4
			
			mov 	ecx,fSize
			cmp 	ecx,128
			jb 		@F
			sub 	ecx,128+1
			invoke 	SetFilePointer,hFile,ecx,0,FILE_BEGIN
			invoke 	ReadFile,hFile,esi,4,ADDR lbrw,0
			cmp 	dword ptr [esi],047415400h
			.if 	zero?
				mov 	[ScannableFileObject.FileType],FILE_TYPE_EXCLUDE
				closef
				SehPop
				return_0
			.endif
			@@:
			
		
		align 4
		
		cmp 	fSize,10
		jbe		@nosize
		
		.if 	!arcfile
			cmp 	fSize,10000000
			jnb 	@nosize
		.endif
		
		align 4
		
		; ------- mapping it ------- ;
		invoke  CreateFileMapping,hFile,0,PAGE_READONLY,0,0,0
		.if     eax
			mov 	fMap,eax
			invoke 	MapViewOfFile,fMap,FILE_MAP_READ,0,0,0
			.if 	eax
				cmp 	eax,-1
				.if 	zero?
					invoke 	CloseHandle,fMap
					jmp 	@nosize
				.endif
				
				; ------- Save it for global use ------- ;
				mov 	memptr,eax
				lea 	eax,ScannableFileObject
				assume 	eax:ptr WORKFILE
				m2m 	[eax].lpVoidMem,memptr
				m2m 	[eax].fMap,fMap
				m2m		[eax].fSize,fSize
				m2m 	[eax].hFile,hFile
				; ------- Get file type  ------- ;
				mov 	esi,memptr
				; ------- If file type = bin or executable file eg. EXE or DLL, so... ------- ;
				; check for MZ sign
				cmp 	word ptr [esi],'ZM'
				jne 	@nobin
				
				; ------- Check to prevent error ------- ;
				mov 	ecx,memptr	
				add 	ecx,03Ch
				mov 	edx,memptr
				add 	edx,fSize
				cmp 	ecx,edx
				jnb 	@nobin
				add 	esi,03Ch ;[esi+03ch]
				add 	si,word ptr [esi]
				sub 	si,03ch
				
				; ------- Check to prevent error ------- ;
				cmp 	esi,edx
				jnb 	@nobin
				
				; ------- Check for PE sign (NT signature) ------- ;
				cmp 	word ptr [esi],'EP'
				jne 	@nobin
				
				; ------- Check for type ------- ;
				assume 	esi:ptr IMAGE_NT_HEADERS
				
				m2m 	[eax].FileType,[esi].FileHeader.Characteristics
				
				assume 	esi:nothing
				
				jmp 	@endl2
				
				align 4
				@nobin:
				
				mov 	esi,memptr
				; ------- check for archive file like zip/rar/tar dll ------- ;
				; ZIP
				lea 	eax,ScannableFileObject
				cmp 	word ptr [esi],'KP'				
				.if 	zero?
					mov 	[eax].FileType,IMAGE_FILE_ZIP
				.else
					mov 	[eax].FileType,IMAGE_FILE_NEUTRAL
				.endif
				
				assume 	eax:nothing
				
				@endl2:
				mov 	retv,eax
			.else
				mov 	esi,CloseHandle
				scall 	esi,fMap
				scall 	esi,hFile
				sub		eax,eax
				mov 	fMap,eax
				mov 	hFile,eax
			.endif
		.else
			invoke 	CloseHandle,hFile
			mov 	hFile,0
		.endif
	.else
		cText	szcannotoopenfileforscanning,"Cannot open file for scanning, file :"
		lea 	esi,szcannotoopenfileforscanning
		invoke 	AppendLogConsole,esi
		invoke 	AppendLogConsole,[lpszFile]
	.endif

	align 4
	; ------- seh trap ------- ;
	SehTrap 	__lsf
		ErrorDump 	"LoadScanableFile",offset LoadScanableFile,offset szEngineAsm
		mWriteError	reparg("In loading file :")
		mWriteError	lpszFile	
	SehEnd 		__lsf
	
	.if 	!retv
		mov 	esi,CloseHandle
		.if 	memptr
			invoke 	UnmapViewOfFile,memptr
		.endif
		.if 	fMap
			scall 	esi,fMap
		.endif
		.if 	hFile
			scall 	esi,hFile
		.endif
	.endif
	
	mov 	eax,retv    
    ret
@nosize:	; ------- error ------- ;
    invoke  CloseHandle,hFile
    mov 	hFile,0
    SehPop
    return_0

LoadScanableFile endp

align 16

; ------- Clear map & scannable work file handle ------- ;
CloseScanableFile proc uses esi ebx
	
	; ------- seh installation ------- ;
	SehBegin 	__csf
	
	lea 	esi,ScannableFileObject
	assume 	esi:ptr WORKFILE
	mov 	ecx,[esi].lpVoidMem
	.if 	ecx
		invoke	UnmapViewOfFile,ecx
		mov 	[esi].lpVoidMem,0	; <-- reset ;
	.endif
	mov 	ebx,CloseHandle
	mov 	ecx,[esi].fMap
	.if 	ecx
		scall 	ebx,ecx
		mov 	[esi].fMap,0	; <-- reset ;
	.endif
	mov 	ecx,[esi].hFile
	.if 	ecx
		scall 	ebx,ecx
		mov 	[esi].hFile,0	; <-- reset ;
	.endif 	
	assume 	esi:nothing
	
	; ------- seh trapper ------- ;
	SehTrap 	__csf
		ErrorDump 	"CloseScanableFile",offset CloseScanableFile,"engine.asm"
	SehEnd 		__csf
	
	ret

CloseScanableFile endp

align 16

.data?
	szPackerInfo db 256 dup(?)
.code

GetPackInfoz proc uses eax ecx pcode:DWORD
	
	mov  	edx,offset szPackerInfo
	push 	edx
	
	mov 	eax,pcode
	.if 	eax == PACKER_ASPACK
		push 	reparg("ASPack")
	.elseif 	eax == PACKER_FSG
		push 	reparg("FSG")
	.elseif 	eax == PACKER_MEW
	.elseif 	eax == PACKER_NPACK
	.elseif 	eax == PACKER_PETITE
	.elseif 	eax == PACKER_TELOCK
	.elseif 	eax == PACKER_UPX
		push 	reparg("UPX")
	.elseif 	eax == PACKER_WINUPACK
	.elseif 	eax == PACKER_PEC2
		push 	reparg("PECompact")
	.else
		push 	reparg("UNKNOWN")
	.endif
	
	scall 	wsprintf,edx,reparg("%s PE bundle detection")
	add 	esp,3*4
	pop 	[gTFI.lpszInfo]
	
	ret

GetPackInfoz endp

align 16

CheckPackUnpack proc uses edi esi ebx ibase:DWORD,isize:DWORD
	
	xor 	eax,eax
	mov 	PackerIs,eax
	cmp 	_WhatThePackerEx,eax
	jne 	@F
		ret
	@@:
	
	msign 	esi
	
	push 	isize
	push 	ibase
	call 	_WhatThePackerEx
	mov 	PackerIs,eax
	
	push 	isize
	push 	ibase
	.if 	eax==PACKER_UPX
		call 	upx_unpack_all	;,ibase,isize
		.if 	eax
			scall 	GetPackInfoz,PACKER_UPX
		.endif
		ret
	.elseif 	eax==PACKER_ASPACK
		call 	aspack_unpack_all ;,ibase,isize
		.if 	eax
			scall 	GetPackInfoz,PACKER_ASPACK
		.endif
		ret
	.elseif 	eax==PACKER_FSG
		call 	fsg_unpack_all ;,ibase,isize
		.if 	eax
			scall 	GetPackInfoz,PACKER_FSG
		.endif
		ret
	.elseif 	eax==PACKER_PEC2
		call 	pecompact_unpack_all
		.if 	eax
			scall 	GetPackInfoz,PACKER_PEC2
		.endif
		ret
	.endif
	add 	esp,08h
	
	xor 	eax,eax
	ret
CheckPackUnpack endp

align 16

; ------- Generic detection uses string faker method ------- ;
CheckFileByString proc uses edi esi lpszPathFile:DWORD
	
	LOCAL 	len,Ext1,Ext2:DWORD
	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	LOCAL 	lBuff2[MAX_PATH+1]:BYTE
	LOCAL 	retv:DWORD
	
	
	; ------- SEH Installation ------- ;
	SehBegin	__cfbs
	
	mov 	retv,0
	mov 	eax,lpszPathFile
	cmp 	byte ptr [eax],0
	jnz 	@F
		SehPop
		return_0
	@@:
	invoke 	MyZeroMemory,ADDR lBuff,MAX_PATH
	
	; ------- Get file name only ------- ;
	invoke 	OnlyFileName,ADDR lBuff,lpszPathFile
	
	; ------- Now, Process filename string ------- ;
	; kill all space char
	Invoke 	KillSpace,ADDR lBuff,MAX_PATH
	test 	eax,eax
	jz 		@endl
	
	mov 	len,eax ; new length for new string
	
	; ------- Now check for double extention ------- ;
	lea 	esi,lBuff
	mov 	ecx,len
	@lp:
		cmp 	byte ptr [esi+ecx],'.'
		je 		@next_ext
	Loop 	@lp
	
	; ------- Nothing ------- ;
	; not suspected
	
	jmp 	@endl
@next_ext:	; ------- Check level 1 ------- ;
	
	; ------- First ext grabbed ------- ;
	mov 	eax,esi
	add 	eax,ecx
	mov 	Ext1,eax
	dec 	ecx
	test 	ecx,ecx
	js		@exnf
	jz		@exnf
	
	; ------- Check for second ext ------- ;
	@lp2:
		cmp 	byte ptr [esi+ecx],'.'
		je 		@suspect
	Loop 	@lp2

@exnf:
	; ------- second ext not found, so.. ------- ;
	; check for long space char

	invoke 	GetSpaceOnly,ADDR lBuff2,lpszPathFile,MAX_PATH
	test 	eax,eax
	jz 		@endl
	
	; ------- Check for space long ------- ;
	mov 	ecx,17
	lea 	edi,lBuff2
	mov 	al,' '
	repe 	scasb
	
	; ------- check for ecx ------- ;
	; if ecx = 0 then suspect found, but check for runnable ext first
	test 	ecx,ecx
	jnz 	@endl
	
	invoke 	IsRunnable,Ext1
	mov 	retv,eax
	
	@@:
	jmp 	@endl
@suspect: ; ------- Check level 2 ------- ;

	test 	ecx,ecx
	jz 		@endl
	
	mov 	eax,esi
	add 	eax,ecx
	inc 	eax
	mov 	Ext2,eax
	
	; ------- Kill dot char ------- ;
	
	lea eax,lBuff
	strlen eax
	
	lea 	ecx,lBuff
	add 	ecx,eax
	sub 	ecx,Ext2
	invoke 	ReplaceChar,Ext2,'.',0,ecx
	
	; ------- Now, check for important ext ------- ;
	lea 	edi,szImportantExt
	@lp3:
		invoke 	lstrcmpi,Ext2,edi
		je 		@suspect2
	NextArray 	@lp3
	
	; ------- Nothing ------- ;
	jmp 	@endl
@suspect2:	; ------- Check level 3 ------- ;
	
	; ------- Is main Ext runnable? ------- ;
	mov 	edi,Ext1
	mov 	al,'.'
	stosb
	invoke 	IsRunnable,Ext1
	test 	eax,eax
	jz 		@endl
	
	; ------- Suspect detected!! ------- ;
	mov 	retv,eax

@endl:

	; ------- SEH Handler for CheckFileByString ------- ;
	SehTrap 	__cfbs
		ErrorDump 	"CheckFileByString",offset CheckFileByString,offset szEngineAsm
	SehEnd 		__cfbs

	mov 	eax,retv
	ret

CheckFileByString endp

align 16
                            
CheckWithSVEx proc uses edi esi
    
    LOCAL 	vSignLength,dwHit:DWORD
    LOCAL 	vSignBuffer[30+1]:BYTE   
    LOCAL 	retv,plvi:DWORD
    LOCAL 	AlreadyUsedExVdb:DWORD
    
    ; ------- Set SEH ------- ;
    SehBegin    __cwse
    
    sub 	eax,eax
    mov     retv,eax
    mov 	plvi,eax
    mov 	AlreadyUsedExVdb,eax
    
    lea 	esi,AnsavVDBv2 ; load VDBv2
    
    cmp 	byte ptr [esi],0
    je 		@usesexvdb
    
    assume 	esi:ptr SVDBv2
    
    align 4
    
    ; ------- Check begin ------- ;
    ; check first for file size
    ; keep from error
@check_again:
	mov 	edi,[ScannableFileObject.lpVoidMem] ; file memptr
    mov 	ecx,[ScannableFileObject.fSize]
    mov 	eax,[esi].dwSignOffset
    add 	eax,[esi].dwSignLength
    cmp 	eax,ecx
    jnb 	@next_db
    
    ; ------- Check for DB (is listed?) ------- ;
    cmp 	[esi].fOnlyShow,1
    je		@next_db
    
    ; ------- check for virus type (EXE) ------- ;
    test 	[esi].uVirusInfo.dwType,VIRI_EXE
    jz	 	@noexe
    ; ------- If EXE check for valid PE first ------- ;

	test  	[ScannableFileObject.FileType],IMAGE_FILE_DLL
	jnz		@next_db
		; ------- is neutral? ------- ;
		cmp 	[ScannableFileObject.FileType],IMAGE_FILE_NEUTRAL
		je 		@next_db
	jmp		@nodll
	
	align 4
@noexe:
	; ------- Check for virus type (DLL) ------- ;
	test 	[esi].uVirusInfo.dwType,VIRI_DLL
	jz	 	@nodll
	; ------- If DLL check for valid DLL ------- ;
	
	test 	[ScannableFileObject.FileType],IMAGE_FILE_DLL
	jz 		@next_db

	jmp 	@start_scan
	align 4
@nodll:

@start_scan:
	; ------- Get vSign length ------- ;
	sub 	ecx,ecx
	sub 	ecx,1
	push 	edi
		
		lea 	edi,[esi].szVirusSign
		strlen 	edi
		mov 	vSignLength,eax
	pop 	edi

	; ------- Lets checking ------- ;
	lea 	ebx,vSignBuffer
	invoke 	MyZeroMemory,ebx,30
	; goto sign offset
	add  	edi,[esi].dwSignOffset
	sub 	ecx,ecx
	mov 	dwHit,ecx
@buffering:
	; check for printable char
	mov 	al,[edi]
	cmp 	al,32
	jb 		@unlike_char
	cmp 	al,126
	ja 		@unlike_char
	
	; ------- copy it to buffer ------- ;
	mov 	byte ptr [ebx],al
	
	xor		eax,eax
	inc 	eax
	
	add 	dwHit,eax
	
	add 	edi,eax
	add 	ecx,eax
	add 	ebx,eax
	jmp 	@uninc
	
	align 4
	
@unlike_char:
	add 	edi,1
	add 	ecx,1
@uninc:
	; prevent buffer overflow
	mov 	eax,dwHit
	cmp 	eax,vSignLength
	ja		@next_db
	cmp 	ecx,[esi].dwSignLength
	jb  	@buffering
	
	; ------- compare with virus sign ------- ;
	push 	esi
	push 	edi
		lea 	edi,vSignBuffer
		sub 	ebx,edi
		cmp 	ebx,vSignLength
		jne 	@next_db_pop
		
		mov 	edx,ebx
		mov 	ecx,ebx
		and 	edx,3
		shr 	ecx,2
		
		repe	cmpsd ; 32 bit compare
		
		jne 	@next_db_pop
		or 		ecx,edx
		jz		@dcmp
		repe	cmpsb
@dcmp:
		test 	ecx,ecx
		jz 		@threat_detected
@next_db_pop:
	pop 	edi
	pop 	esi
    
    align 4
    
@next_db: ; ------- Get next db ------- ;
    add 	esi,sizeof 	SVDBv2
    cmp 	byte ptr [esi],0
    jne 	@check_again
    
    
    ; ------- internal database closed, now uses external database if available ------- ;
    .if 	ExternalVdb && ExternalVdbSize && !AlreadyUsedExVdb
@usesexvdb:
    	mov 	esi,ExternalVdb
    	add 	esi,sizeof EXVDBINFO
    	mov 	AlreadyUsedExVdb,1
    	jmp 	@check_again
    	nop
    	nop
    .endif
    
    jmp 	@endl
    nop
    nop
    align 4
@threat_detected:
    
    ; ------- Threat detected ------- ;
    
    add 	esp,4 ; fix stack
    pop 	esi
    
    mov 	plvi,esi
    lea 	eax,[esi].szThreatName
    mov 	retv,eax
    
    assume 	esi:nothing
    
@endl:

	align 4
    ; ------- Seh handler ------- ;
    SehTrap     __cwse
IFNDEF	SERVICE
        ErrorDump "CheckWithStEx",offset CheckWithSVEx,offset szEngineAsm
ENDIF
    SehEnd      __cwse
    
    mov     eax,retv
    mov 	ecx,plvi
    ret

CheckWithSVEx endp

align 16

;------------------------------------------------------------------------------;
;
;	BMBinSearchSia : modified by anvie 10-10-2007
;					 added support mask search pattern
;
;
;------------------------------------------------------------------------------;

BMBinSearchSia proc startpos:DWORD,
                 lpSource:DWORD,srcLngth:DWORD,
                 lpSubStr:DWORD,subLngth:DWORD,exc:DWORD

  ; -----------------------------------------------------------------
  ; This version uses four heuristics, it determines the shift type
  ; from the character in the table, if the character is not in the
  ; pattern, it performs a BAD CHARACTER shift, if the character is
  ; in the pattern, it determines if it is the first comparison after
  ; the shift and adds the GOOD SUFFIX shift to the location counter.
  ; If the comparison is not the first after the shift, it calculates
  ; the GOOD SUFFIX shift and adds it to the location counter.
  ; -----------------------------------------------------------------

    LOCAL cval   :DWORD
    LOCAL shift_table[256]:DWORD
    LOCAL excluder:BYTE

    push ebx
    push esi
    push edi
    
	; ------- seh installation ------- ;
	SehBegin 	__bbss
    
    mov 	eax,exc
    mov 	excluder,al

    mov ebx, subLngth

    cmp ebx, 1
    jg @F
    mov eax, -2                 ; string too short, must be > 1
    jmp Cleanup
  @@:

    mov esi, lpSource
    add esi, srcLngth
    sub esi, ebx
    mov edx, esi            ; set Exit Length

  ; ----------------------------------------
  ; load shift table with value in subLngth
  ; ----------------------------------------
    mov ecx, 256
    mov eax, ebx
    lea edi, shift_table
    rep stosd

  ; ----------------------------------------------
  ; load decending count values into shift table
  ; ----------------------------------------------
    mov ecx, ebx                ; SubString length in ECX
    dec ecx                     ; correct for zero based index
    mov esi, lpSubStr           ; address of SubString in ESI
    lea edi, shift_table

    xor eax, eax

  Write_Shift_Chars:
    mov al, [esi]               ; get the character
    inc esi
    
    mov [edi+eax*4], ecx        ; write shift for each character
    dec ecx                     ; to ascii location in table
    jnz Write_Shift_Chars

  ; -----------------------------
  ; set up for main compare loop
  ; -----------------------------
    mov ecx, ebx
    dec ecx
    mov cval, ecx

    mov esi, lpSource
    mov edi, lpSubStr
    add esi, startpos           ; add starting position

    jmp Pre_Loop

; %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  Calc_Suffix_Shift:
    add eax, ecx
    sub eax, cval               ; sub loop count
    jns Add_Suffix_Shift
    mov eax, 1                  ; minimum shift is 1

  Add_Suffix_Shift:
    add esi, eax                ; add SUFFIX shift
    mov ecx, cval               ; reset counter in compare loop

  Test_Length:
    cmp edx, esi                ; test exit condition
    jl No_Match

  Pre_Loop:
  
  	; butuh dibetulin!
  	lea 	eax,[esi+ecx]
    mov 	edx,lpSource
    add 	edx,srcLngth
    cmp 	eax,edx
    ja		No_Match
    ; ------- bug fixed ------- ;
	.if 	!UnpackedData
	    mov 	edx,[ScannableFileObject.lpVoidMem]
	    add 	edx,[ScannableFileObject.fSize]
    .endif
    cmp 	eax,edx
    ja		No_Match
    ; -------------- ;
  
    xor eax, eax                ; zero EAX for following partial writes
    
    mov al, [esi+ecx]
    
    mov dl, excluder
    cmp byte ptr [edi+ecx],dl
    jne	@F
    	dec 	ecx
    	jmp 	Cmp_Loop
    @@:
    
    cmp al, [edi+ecx]           ; cmp characters in ESI / EDI
    je @F
    mov eax, shift_table[eax*4]
    cmp ebx, eax
    jne Add_Suffix_Shift        ; bypass SUFFIX calculations
    lea esi, [esi+ecx+1]        ; add BAD CHAR shift
    jmp Test_Length
  @@:
    dec ecx
    xor eax, eax                ; zero EAX for following partial writes

  Cmp_Loop:
    mov al, [esi+ecx]
    
    mov dl, excluder
    cmp byte ptr [edi+ecx],dl
    jne	@F
    	dec 	ecx
    	jns 	Cmp_Loop
    	jmp 	Match
    @@:
    
    cmp al, [edi+ecx]           ; cmp characters in ESI / EDI
    jne Set_Shift               ; if not equal, get next shift
    dec ecx
    jns Cmp_Loop
    jmp Match                   ; fall through on match

  Set_Shift:
    mov eax, shift_table[eax*4]
    cmp ebx, eax
    jne Calc_Suffix_Shift       ; run SUFFIX calculations
    lea esi, [esi+ecx+1]        ; add BAD CHAR shift
    jmp Test_Length

; %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  Match:
    sub esi, lpSource           ; sub source from ESI
    mov eax, esi                ; put length in eax
    jmp Cleanup

  No_Match:
    mov eax, -1

  Cleanup:
	SehPop
	
 CleanUp2:
    pop edi
    pop esi
    pop ebx

    ret
    
	SehTrap 	__bbss
	SehEnd 		__bbss
	xor 	eax,eax
	dec 	eax
	jmp 	CleanUp2
	ret    

BMBinSearchSia endp

align 16

RoundSize 	PROTO :DWORD,:DWORD


; ------- uses SIA engine ------- ;
CheckWithSiaEx	proc uses edi esi ebx lpszFile:DWORD

	LOCAL 	CompareCount:DWORD
	LOCAL 	MaxMemReady:DWORD
	LOCAL 	retv:DWORD
	LOCAL 	ScanMethod,PageWork,PageSize,PageMax:DWORD
	LOCAL 	EntryP,SectionNum,tmp:DWORD
	LOCAL  	Ovld,OvldSize:DWORD
	
	; ------- seh installation ------- ;
	SehBegin 	__cwsiae
	
	sub 	eax,eax
	mov 	retv,eax
	mov 	Ovld,eax
	mov 	UnpackedData,eax
	
	; ------- check min size  ------- ;
	mov 	ecx,[ScannableFileObject.fSize]
	cmp		ecx,32
	ja 		@F
		SehPop
		xor 	eax,eax
		ret
	@@:
	
	; ------- check max size ------- ;
	cmp 	ecx,50000000
	jb 		@F
		SehPop
		xor 	eax,eax
		ret
	@@:
	
	lea 	ebx,SIAVDBV2DATA
	; check size
	assume 	ebx:ptr SIAVDBv2
	
	align 4
	
	lea 	edx,ScannableFileObject
	test 	[edx.WORKFILE].FileType,IMAGE_FILE_EXE
	jz 		@nonpe
	; ------- check for packed image and unpack it if possible ------- ;
	invoke 	CheckPackUnpack,[ScannableFileObject.lpVoidMem],[ScannableFileObject.fSize]
	.if 	eax
		mov 	UnpackedData,eax
		mov 	PageSize,ecx
	.endif
	; -------------- ;
	
@nonpe:
	align 4
	
@scanagain:
	; ------- Check for file type ------- ;
	lea 	edx,ScannableFileObject
	movzx 	ecx,[ebx].uVirusInfo.dwType
	
	test 	ecx,VIRI_EXE
	jz		@nx
		test 	[edx.WORKFILE].FileType,IMAGE_FILE_DLL
		jnz 	@nextdb
		cmp 	[edx.WORKFILE].FileType,IMAGE_FILE_NEUTRAL
		je 		@nextdb
		; don't scan arc
		cmp 	[edx.WORKFILE].FileType,IMAGE_FILE_ZIP
		je 		@nextdb
		
		jmp 	@beginscan
@nx:
	test 	ecx,VIRI_DLL
	jz		@nx2
		test 	[edx.WORKFILE].FileType,IMAGE_FILE_DLL
		jz		@nextdb
		cmp 	[edx.WORKFILE].FileType,IMAGE_FILE_NEUTRAL
		jz		@nextdb
		; don't scan arc
		cmp 	[edx.WORKFILE].FileType,IMAGE_FILE_ZIP
		je 		@nextdb
@nx2:

	
@beginscan:;-------------------------------------- BEGIN SCAN ----------------------------------------;
	align 4
	
	; ------- if image unpack available ------- ;
	.if 	UnpackedData
		mov2 	PageWork,UnpackedData
		jmp 	@skipseccheck
		nop
		nop
	.endif
	
	; ------- get page (work) area ------- ;
	; optimized
	mov 	ScanMethod,SECTION_ALLWOVL
	mov 	ecx,[edx.WORKFILE].lpVoidMem
	mov 	PageWork,ecx
	mov 	eax,[edx.WORKFILE].fSize
	mov 	PageSize,eax
	add 	eax,ecx
	mov 	PageMax,ecx

	align 4
	
	; skip non pe image
	.if 	!([ebx].uVirusInfo.dwType & VIRI_EXE) && \
			!([ebx].uVirusInfo.dwType & VIRI_DLL) 
		jmp 	@skipseccheck
	.endif
	
	mov 	edi,[edx.WORKFILE].lpVoidMem
	add 	edi,03ch
	add 	di,[edi]
	sub 	di,03ch
	
	m2m 	EntryP,[edi.IMAGE_NT_HEADERS].OptionalHeader.AddressOfEntryPoint
	movzx 	eax,[edi.IMAGE_NT_HEADERS].FileHeader.NumberOfSections
	mov 	tmp,eax
	mov 	SectionNum,eax
	
	assume 	edi:ptr IMAGE_SECTION_HEADER
	
	; get section location to map
	mov 	eax,[ebx].lpSection
	test 	eax,SECTION_CODE ; unwriteable
	.if 	!zero?
		align 4
		
		; goto section header
		add 	edi,sizeof IMAGE_NT_HEADERS
		; skip zero raw size
		sub 	eax,eax
		@@:
			cmp 	[edi].Misc.PhysicalAddress,eax
			db 3eh
			je 		@zeroskip
			cmp 	[edi].Misc.VirtualSize,eax
			je 		@zeroskip
			cmp 	[edi].VirtualAddress,eax
			db 3eh
			je		@zeroskip
			cmp 	[edi].PointerToRawData,eax
			je 		@zeroskip
			cmp 	[edi].SizeOfRawData,eax
			db 3eh
			je		@zeroskip
				test 	[edi].Characteristics,IMAGE_SECTION_EXECUTABLE
				.if 	!zero?
					mov 	eax,[edi].VirtualAddress
					jmp 	@sectionok
				.endif
			@zeroskip:
			add 	edi,sizeof IMAGE_SECTION_HEADER
			sub 	tmp,1	; <-- optimized ;
		jnz 	@B
		; no match
		jmp @skipseccheck
	.elseif (eax & SECTION_ENTRYP)
		mov 	esi,edx ; keep not use stack
		invoke 	ImageRvaToSection,edi,[edx.WORKFILE].lpVoidMem,EntryP
		mov 	edx,esi
		test 	eax,eax
		jz 		@skipseccheck
		mov 	edi,eax
		mov 	eax,EntryP
	.elseif (eax & SECTION_DATA)
		; goto section header
		add 	edi,sizeof IMAGE_NT_HEADERS
		; skip zero raw size
		sub 	eax,eax
		@@:
			db 3eh
			cmp 	[edi].Misc.PhysicalAddress,eax
			je 		@zeroskip2
			cmp 	[edi].Misc.VirtualSize,eax
			je 		@zeroskip2
			db 3eh
			cmp 	[edi].VirtualAddress,eax
			je		@zeroskip2
			db 3eh
			cmp 	[edi].PointerToRawData,eax
			je 		@zeroskip2
			cmp 	[edi].SizeOfRawData,eax
			je		@zeroskip2
				mov 	eax,[edi].Characteristics
				test 	eax,IMAGE_SECTION_READABLE or IMAGE_SECTION_DATA
				.if 	!zero? && !(eax & IMAGE_SECTION_EXECUTABLE)
					mov 	eax,[edi].VirtualAddress
					jmp 	@sectionok
				.endif
			@zeroskip2:
			add 	edi,sizeof IMAGE_SECTION_HEADER
			sub 	tmp,1	; <-- optimized ;
		jnz 	@B
		; no match
		jmp @skipseccheck
	.elseif (eax & SECTION_RDATA)
		; goto section header
		add 	edi,sizeof IMAGE_NT_HEADERS
		; skip zero raw size
		sub 	eax,eax
		@@:
			db 3eh
			cmp 	[edi].Misc.PhysicalAddress,eax
			je 		@zeroskip3
			cmp 	[edi].Misc.VirtualSize,eax
			je 		@zeroskip3
			db 3eh
			cmp 	[edi].VirtualAddress,eax
			je		@zeroskip3
			db 3eh
			cmp 	[edi].PointerToRawData,eax
			je 		@zeroskip3
			cmp 	[edi].SizeOfRawData,eax
			je		@zeroskip3
				mov 	eax,[edi].Characteristics
				cmp 	eax,040000040h
				.if 	zero?
					mov 	eax,[edi].VirtualAddress
					jmp 	@sectionok
				.endif
			@zeroskip3:
			add 	edi,sizeof IMAGE_SECTION_HEADER
			sub 	tmp,1	; <-- optimized ;
		jnz 	@B
		; no match
		jmp @skipseccheck
	.elseif 	(eax & SECTION_ALLNOVL) ; check full image exclude overlays
		
		.if 	!Ovld	; <-- optimized purpose ;
			; ------- check overlays ------- ;
			mov 	esi,edx
			add 	edi,sizeof IMAGE_NT_HEADERS
			mov 	ecx,SectionNum
			mov 	tmp,0
			@lp2:
				invoke 	RoundSize,[edi].SizeOfRawData,200h
				mov 	edx,[edi].PointerToRawData
				add 	edx,[edi].SizeOfRawData
				cmp 	edx,tmp
				jbe 	@F
					mov 	tmp,edx
				@@:
				add 	edi,sizeof IMAGE_SECTION_HEADER
			loop 	@lp2
			mov 	edx,esi
			
			mov 	eax,tmp
			cmp 	eax,[edx.WORKFILE].fSize
			jnb 	@novl
				
				align 4
				
				; set page max
				mov 	eax,tmp
				add 	eax,[edx.WORKFILE].lpVoidMem
				mov 	PageMax,eax
				mov 	Ovld,eax
				sub 	eax,[edx.WORKFILE].lpVoidMem
				mov 	PageSize,eax
				mov 	OvldSize,eax
				
			@novl:
		.else
			mov2 	PageMax,Ovld
			mov2 	PageSize,OvldSize
		.endif
		
		jmp @skipseccheck
	.else
		jmp @skipseccheck
	.endif
	@sectionok:
	
	push 	edx
	invoke 	Rva2Raw,[edx.WORKFILE].lpVoidMem,eax
	.if 	!eax
		; set mode scan to = SECTION_ALLNOVL
		pop 	edx
		jmp 	@skipseccheck
	.endif
	pop 	edx
	
	mov 	esi,eax 
	mov 	ecx,esi
	
	mov 	eax,[edx.WORKFILE].lpVoidMem
	add 	ecx,eax
	
	; ------- check probe for read? ------- ;
	; bug fix
	cmp 	ecx,eax
	jb 		@endl
	add 	eax,[edx.WORKFILE].fSize
	cmp 	ecx,eax
	jnb 	@endl
	; -------------- ;
	
	
	mov 	PageWork,ecx
	
	; get page (work) size
	mov 	eax,[edi].SizeOfRawData
	mov 	PageSize,eax
	add 	eax,ecx
	mov 	PageMax,eax
	
	; not searh check
	test 	[ebx].lpSection,SECTION_NOTSEARCH
	jz 		@skipseccheck
	
	mov 	eax,PageSize
	cmp 	eax,[ebx].dwVDBLength
	jb 		@skipseccheck
	mov 	eax,[ebx].dwVDBLength
	mov 	PageSize,eax
	shl 	eax,1
	add 	eax,ecx
	mov 	PageMax,eax
	
	assume 	edi:nothing
	
	; optimized
	; -------------- ;
		
@skipseccheck:

	test 	[ebx].lpSection,SECTION_NOTSEARCH
	jz		@F
		cmp 	UnpackedData,0
		jne 	@nextdb
	@@:


	mov 	ecx,[ebx].dwVDBLength
	cmp 	ecx,[edx.WORKFILE].fSize
	jnb		@endl
	
	align 4
	
	; ------- Scan mask ------- ;
	
	; optimized
	mov 	edi,PageWork
	; optimized
	
	.if 	UnpackedData
		mov 	ecx,PageWork
		add 	ecx,PageSize
		mov 	PageMax,ecx
	.else
		; ------- optimized  ------- ;
		mov 	ecx,[ScannableFileObject.lpVoidMem]
		add 	ecx,[ScannableFileObject.fSize]
		; ------- optimized  ------- ;
	.endif
	
	mov 	MaxMemReady,ecx
	
	msign 	esi
@scan:
	mov 	esi,[ebx].lpSiaData
	mov 	CompareCount,0
	@lp:
		
		align 4
		
		mov 	eax,edi
		add 	eax,[ebx].dwVDBLength
		
		; optimized
		cmp 	eax,PageMax
		jnb 	@nextdb
		; optimized
		
		cmp 	eax,MaxMemReady
		jnb 	@nextdb
		
		cmp 	eax,PageWork
		jb 		@endl
		
		mov 	ecx,PageSize
		sub 	ecx,[ebx].dwVDBLength
		js		@nextdb		
		
		mov 	eax,PageWork
		add 	eax,ecx
		mov 	edx,PageMax
		sub 	edx,[ebx].dwVDBLength
		cmp 	eax,edx
		ja 		@nextdb
		
		sub 	eax,eax
		mov 	al,[ebx].bSiaExcluder
		invoke 	BMBinSearchSia,0,PageWork,PageSize,[ebx].lpSiaData,[ebx].dwVDBLength,eax
		test 	eax,eax
		jns 	@detected
		jmp 	@nextdb

@nextdb:
	mov 	ecx,[ebx].dwVDBLength
	lea 	ebx,[ebx+ecx+sizeof SIAVDBv2]

	cmp 	byte ptr [ebx],0
	jnz 	@scanagain
	jmp 	@endl
	nop
	nop
@detected:
	
	align 4
	
	lea 	eax,[ebx].szThreatName
	mov 	retv,eax
	
	assume 	ebx:nothing
@endl:

	align 4
	
	; ------- seh trap ------- ;
	SehTrap		__cwsiae
IFNDEF 	SERVICE
		ErrorDump	"CheckWithSiaEx",offset CheckWithSiaEx,offset szEngineAsm
		mWriteError	"In Scanning file :"
		mWriteError	lpszFile
ENDIF
		mov 	retv,0
	SehEnd		__cwsiae

	; ------- free memory if unpacked data exists ------- ;
	.if 	UnpackedData
		vfree 	UnpackedData
	.endif
	; -------------- ;

	mov 	eax,retv
	ret

CheckWithSiaEx endp


align 16

.data?
	szShortPath db (MAX_PATH*4)+4 dup(?)
	TTCWinVis	dd ?
	DontShort	dd ?
.code

FormatShortPath proc uses edi esi lpPath:DWORD
	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	LOCAL 	tmp:BYTE
	LOCAL 	retv:DWORD
	LOCAL	wpc:WINDOWPLACEMENT
	
	; ------- seh installation ------- ;
	SehBegin	__fsp
	
	mov 	eax,TTCWinVis
	.if 	eax > 20
		mov 	TTCWinVis,0
		invoke 	MyZeroMemory,ADDR wpc,sizeof WINDOWPLACEMENT
		mov 	[wpc.iLength],sizeof WINDOWPLACEMENT
		invoke 	GetWindowPlacement,hMainWnd,ADDR wpc
		.if 	[wpc.showCmd] == SW_MAXIMIZE
			mov 	DontShort,1
		.else
			mov 	DontShort,0
		.endif
	.else
		add 	TTCWinVis,1
	.endif
	
	.if 	DontShort
		SehPop
		mov 	eax,lpPath
		ret
	.endif
	
	mov2 	retv,lpPath
	
	strlen lpPath
	.if 	eax > 35
		
		lea 	edi,lBuff
		invoke 	MyZeroMemory,edi,MAX_PATH+1
		invoke 	lstrcpy,edi,lpPath
		invoke 	ReplaceChar,edi,'\',0,MAX_PATH
		
		; ------- get longer path ------- ;
		cld
		mov 	ecx,260
		xor		al,al
		repnz 	scasb
		repnz 	scasb
		@lp:
			xor 	esi,esi
			
			strlen edi
			
			cmp 	eax,11
			jb 		@F
				
				call 	IsArchiveFString
				.if 	!eax
					mov 	esi,edi
					mov 	al,byte ptr [edi]
					mov 	tmp,al
					mov 	byte ptr [edi],5	; <-- sign ;
				.endif
			@@:
			
		NextArray 	@lp
		
		; ------- fix filename ------- ;
		.if 	esi
			mov 	al,tmp
			mov 	byte ptr [esi],al
		.endif 
		
		; ------- rebuild it ------- ;
		lea 	edi,lBuff
		lea 	esi,szShortPath
		invoke 	MyZeroMemory,esi,MAX_PATH
		
		; ------- check for network path ------- ;
		cmp word ptr [edi],0
		jne @F
			mov word ptr [edi],'\\'
		@@:
		
		invoke 	lstrcpy,esi,edi
		cld
		mov 	ecx,MAX_PATH
		xor 	al,al
		repnz 	scasb
		@lp2:
			
			invoke 	TruePath,esi
			cmp 	byte ptr [edi],5
			.if 	zero?
				invoke 	lstrcat,esi,reparg("...")
			.else
				invoke 	lstrcat,esi,edi
			.endif
			
		NextArray 	@lp2
		
		mov 	retv,esi
		
		; ------- seh trapper ------- ;
		SehTrap 	__fsp
			ErrorDump 	"FormatShortPath",offset FormatShortPath,offset szEngineAsm
		SehEnd 		__fsp
		
	.endif
	mov 	eax,retv
	ret

IsArchiveFString:
	push 	edi
	xor 	ecx,ecx
	.while  byte ptr [edi] 	
		cmp 	byte ptr [edi],':'
		.if 	zero?
			add 	ecx,1
			jmp 	@F
		.endif
		add 	edi,1
	.endw
@@:
	pop 	edi
	mov 	eax,ecx
	retn
	
FormatShortPath endp

align 16

FormatArcPath proc uses edi esi lpPath:DWORD
	
	LOCAL 	tc:DWORD
	
	; ------- seh installation ------- ;
	SehBegin	__fap
	
	
	mov 	tc,0
	
	analloc 	MAX_PATH*4
	.if 	eax
		mov 	edi,eax
		mov 	esi,lpPath
		push 	edi
		
		xchg 	edi,esi
		or	 	ecx,-1
		mov 	al,':'
		cld
		repne	scasb
		not 	ecx
		xchg 	edi,esi
		
		sub 	esi,ecx
		rep 	movsb
		
		@lp:
			lodsb
			cmp 	al,':'
			jne 	@F
				add 	tc,1
				mov 	word ptr [edi],'[:'
				add 	edi,2
				lodsb
				cmp 	al,'['
				jne 	@F
				lodsb
			@@:
			mov 	[edi],al
			add 	edi,1
			cmp 	al,0
			jne		@lp
			
		mov 	ecx,tc
		.if 	ecx
			sub 	ecx,1
			sub 	edi,1
			mov 	al,']'
			rep 	stosb
		.endif
		
		pop 	edi
		invoke 	lstrcpy,lpPath,edi
		anfree 	edi
	.endif
	
	SehTrap 	__fap
		ErrorDump 	"FormatArcPath",offset FormatArcPath,offset szEngineAsm
	SehEnd 		__fap
	ret

FormatArcPath endp

align 16

; ------- Procedure for checking file  ------- ;
CheckThisFile 	proc uses ebx esi edi lpszFile:DWORD,lpTFI:DWORD ;,HKTest:DWORD
	LOCAL 	retv:DWORD
	LOCAL 	ZipScanFormat:DWORD
	LOCAL 	ShortPath:DWORD
	
	; ------- seh installation ------- ;
	SehBegin	__ctf
		
	mov 	retv,0
	mov 	FileScanAborted,0

	.if 	!MemCheck
	    .if 	InsideZip
	    	
	    	xor 	edi,edi
	    	valloc (MAX_PATH*4)+1
	    	.if 	eax
	    		mov 	edi,eax
	    		
	    		mov 	esi,lpszFile
	    		
	    		@@:
	    			lodsb
	    			cmp 	al,0
	    			je 		@F
	    			cmp 	dword ptr [esi],'pmt.'
	    			jne 	@B
	    		@@:
	    		add 	esi,5
	    		@@:
	    			lodsb
	    			cmp 	al,0
	    			je 		@F
	    			cmp 	al,'\'
	    			jne 	@B
	    		@@:

	    		invoke 	wsprintf,edi,reparg("%s:[%s]"),ZipFileName,esi
	    		invoke 	FormatArcPath,edi
	    		mov 	ZipScanFormat,0
	    		valloc  (MAX_PATH*8)+1
	    		.if 	!eax
	    			mov2 ZipScanFormat,offset szErrMem
	    		.endif
	    		mov 	ZipScanFormat,eax
	    		
	    		invoke 	lstrcpy,ZipScanFormat,edi
	    		invoke 	FormatShortPath,edi
	    	.endif
	    .else
	    	invoke 	FormatShortPath,lpszFile
	    .endif
	    
	    invoke 	SetWindowText,hMainEditPath, eax ;lpszFile
	    
	    .if 	InsideZip
	    	.if 	edi
	    		vfree edi
	    	.endif
	    .endif
	.endif

	.if 	!MemCheck && !SingleCheck && !InsideZip
	    add 	MainPBPos,1
	    
	    mov 	esi,SetWindowText
	     
	    invoke 	SendMessage,hMainProgBar,PBM_SETPOS,MainPBPos,0
	    invoke 	wsprintf,ADDR szCheckedFilesCountBuff,ADDR szdTosF,MainPBPos
	    lea 	eax,szCheckedFilesCountBuff
	    scall 	esi,hTxtCheckedFiles,eax
	    invoke 	PercentThis,MainPBPos,AllFilesCount
	    .if 	eax!=LastPercentValue
	    	invoke 	wsprintf,ADDR szPercentBuff,ADDR szPercentF,eax
	    	lea 	eax,szPercentBuff
	    	scall 	esi,hTxtMainPercent,eax
	    .endif
		mov 	LastPercentValue,eax
	.endif
	                                                                               ; ------- Scan LEVEL - ;
	; ------- First, scan with string  ------- ;				    ; --------------------[ -= LEVEL 1 =- ]

	invoke 	CheckFileByString,lpszFile
	.if 	eax
		; ------- Generic Threats (Suspect) detected ------- ;
		mov 	retv,eax
		
		mov 	edi,lpTFI
		assume 	edi:ptr THREATFULLINFO
		
		lea 	eax,[edi].szFilePath
		invoke 	lstrcpyn,eax,lpszFile,MAX_PATH
		invoke 	QGetFileSize,lpszFile
		mov 	[edi].fSize,eax
		
		lea 	eax,[edi].szThreatName
		lea 	edx,szSuspected1
		invoke 	lstrcpyn,eax,edx,30
		mov 	[edi].uVirusInfo.Risk,0 ; VIRI_RISK_UNKNOWN
		mov2 	[edi].uVirusInfo.Description,offset szFakeExt
		mov 	[edi].lpszInfo,0
		assume 	edi:nothing
		
		
		; ------- console log ------- ;
		mov 	ebx,AppendLogConsole
		lea 	eax,szThisFile
		scall 	ebx,eax
		scall 	ebx,lpszFile
		lea 	eax,szDetectedUsesL1
		scall	ebx,eax
		
		jmp 	@endl
	.endif
	
	mLog 	"..nothing"
	
	; ------- Load work file ------- ;
	invoke 	LoadScanableFile,lpszFile
	.if 	eax
		
		
		mov 	edi,lpTFI

		assume 	edi:ptr THREATFULLINFO
		mov2 	[edi].fSize,[ScannableFileObject.fSize]
		assume 	edi:nothing
		
		cmp 	ArcReady,0
		je 		@noarc
		cmp 	hArcMod,0
		je 		@noarc
		
		; ------- check for archive file ------- ;
		cmp 	[ScannableFileObject.FileType],IMAGE_FILE_ZIP
		.if 	zero?
			
			; ------- check for max (limit) archive size to scan ------- ;
			mov 	ecx,LimitArcSizeTS
			jecxz	@F
			cmp 	[ScannableFileObject.fSize],ecx
			jb		@F	
				
				; ------- arc scan skipped ------- ;
				invoke 	AppendLogConsole,reparg("Archive file check skipped (max size limit rule) :")
				invoke 	AppendLogConsole,lpszFile 
				jmp 	@nousesthis
				
			@@:
			
			mov 	edi,lpszFile
			
			strlen edi
			
			mov 	ecx,eax
			@@:
				cmp 	byte ptr [edi+ecx],'.'
				je 		@F
				loop 	@B
			@@:
			add 	edi,ecx
			add 	edi,1
			invoke 	lstrcmpi,edi,reparg("jar")
			.if 	zero?
				.if 	!JAR
					jmp 	@noarc
				.endif
			.endif
			invoke 	lstrcmpi,edi,reparg("zip")
			.if 	zero?
				.if 	!ZIP
					jmp 	@noarc
				.endif
			.endif
			
			; ------- extract archive to temp ------- ;
			.if 	ArcReady
				push ebx
				push esi
				push edi
				
				mov 	edi,AppendLogConsole
				
				invoke 	SetMainTxtStatus2,reparg("[ Extracting... ]"),0
				scall 	edi,reparg("Extracting archive file :")
				scall 	edi,lpszFile
				
				.if 	!InsideZip; ------- MAIN ROOT ARCHIVE ------- ;
					mov 	eax,lpszFile
					mov 	RootZipFileName,eax
					mov 	ZipFileName,eax
					xor 	eax,eax
					mov 	ThreatPathDetected,eax
					mov 	NumThreatInsideArc,eax
				.else
					valloc 	MAX_PATH*4
					.if 	eax
						mov 	esi,eax
						
						invoke 	lstrcpy,esi,ZipFileName
						invoke 	lstrcat,esi,offset sztt2
						
						strlen esi
						
						push 	esi
						add 	esi,eax
						invoke 	OnlyFileName,esi,lpszFile
						pop 	esi
						invoke 	lstrcpy,offset szScanBuff,esi
						mov 	ZipFileName,offset szScanBuff
						
						vfree 	esi
					.endif
				.endif
				
				add 	InsideZip,1
				valloc  MAX_PATH
				.if 	eax
					mov 	esi,eax
					mov 	edi,esi
					
					invoke 	lstrcpy,esi,offset szAnsavTempWorkDir
					invoke 	TruePath,esi
					
					strlen esi
					
					mov 	ecx,eax
					add 	ecx,2
					cld
					@lp:
						lodsb
						cmp al,0
						jne @lp
					sub 	esi,1
					invoke 	OnlyFileName,esi,lpszFile
					
					call 	CloseScanableFile
					
					push 	edi
					call 	[ZII.BuildDirectory]
					add 	esp,4h
					
					push 	eax
					push 	lpszFile
					call 	[ZII.ExtractAllTo]
					add 	esp,4*2
					
					test 	eax,eax	; <-- If extract failed, cancel it ;
					.if 	zero?
						push 	edi
						call 	GenocideThisPath
						pop edi
						pop esi
						pop ebx
						sub 	InsideZip,1
						mov 	esi,AppendLogConsole
						
						scall 	esi,reparg("Extraction failed for this file :")
						scall 	esi,lpszFile
						.if 	InsideZip<2
							mov 	FileScanAborted,1
						.endif
						
						.if 	InsideZip>1
							mov 	esi,ZipFileName
							
							strlen esi
							
							mov 	ecx,eax
							test 	ecx,ecx
							jz		@nonow2
							add 	esi,ecx
							@@:
								cmp 	byte ptr [esi],':'
								je 		@F
								sub 	esi,1
							loop 	@B
							@@:
							mov 	byte ptr [esi],0
						@nonow2:
						.endif
						
						jmp 	@endl
					.endif
					
					StatusChecking
					
					push 	edi
					call 	CheckThisPath
					push 	edi
					call 	GenocideThisPath
					
					; ------- fix arc root path ------- ;
					.if 	InsideZip>1
						mov 	esi,ZipFileName
						
						strlen  esi
						
						mov 	ecx,eax
						test 	ecx,ecx
						jz		@nonow
						add 	esi,ecx
						@@:
							cmp 	byte ptr [esi],':'
							je 		@F
							sub 	esi,1
						loop 	@B
						@@:
						mov 	byte ptr [esi],0
					@nonow:
					.else
						mov2 	ZipFileName,RootZipFileName
					.endif
					
					vfree 	edi
				.else
					mov 	edi,AppendLogConsole
					
					scall 	edi,reparg("Cannot allocate memory for extracting archive file :")
					scall 	edi,lpszFile
				.endif
				pop edi
				pop esi
				pop ebx
				dec 	InsideZip
			.endif	; <-- ArcReady ;
			
			.if 	!InsideZip
				invoke 	QGetFileSize,RootZipFileName
				mov 	edx,lpTFI
				mov 	[edx.THREATFULLINFO].fSize,eax
				mov2 	retv,ThreatPathDetected
			.endif
			jmp 	@endl
		.endif
		@noarc:
		                                                                           ; ------- Scan LEVEL - ;
		; --------------------[ -= LEVEL 2 =- ]
		mLog 	"-Try to check uses level 2 (sv engine)"
		
		call 	CheckWithSVEx
		.if 	eax
			; ------- Virus detected!! ------- ;
			mov 	retv,eax
			
			mov 	esi,ecx ; esi = ptr to cur SVDBv2
			mov 	edi,lpTFI
			assume 	edi:ptr THREATFULLINFO
			assume 	esi:ptr SVDBv2
			
			m2m 	[edi].uVirusInfo.dwType,[esi].uVirusInfo.dwType
			m2m 	[edi].uVirusInfo.dwCleanable,[esi].uVirusInfo.dwCleanable
			m2m 	[edi].uVirusInfo.Risk,[esi].uVirusInfo.Risk
			lea		eax,[edi].szThreatName
			lea 	edx,[esi].szThreatName
			invoke 	lstrcpyn,eax,edx,30
			m2m 	[edi].uVirusInfo.Description,[esi].uVirusInfo.Description
			mov 	[edi].lpszInfo,0
			assume 	esi:nothing
			assume 	edi:nothing
			
			; ------- console log ------- ;
			mov 	ebx,AppendLogConsole
			lea 	eax,szThisFile
			scall 	ebx,eax
			scall 	ebx,lpszFile
			lea 	eax,szDetectedUsesL2
			scall	ebx,eax 
		.else
			; ------- Check with SIA ------- ;						; --------------------[ -= LEVEL 3 =- ]
			cmp 	ScanLevel,2
			jb		@nousesthis	; <-- SCAN LEVEL CHECK ;	
			
			mov 	[gTFI.lpszInfo],0
			
;			; ------- ; ------- ; ------- ; -------  ------- ; ------- ; ------- ; ------- ;
;			; ------- ; ------- ; ------- ; -------  ------- ; ------- ; ------- ; ------- ;
;			; ------- ; ------- ; ------- ; -------  ------- ; ------- ; ------- ; ------- ;
;			; ------- ; ------- ; ------- ; -------  ------- ; ------- ; ------- ; ------- ;
;			; ------- ; ------- ; ------- ; -------  ------- ; ------- ; ------- ; ------- ;
;			; ------- ; ------- ; ------- ; -------  ------- ; ------- ; ------- ; ------- ;
;			; ------- ; ------- ; ------- ; -------  ------- ; ------- ; ------- ; ------- ;
;			;-------------------------------------- IN BENCHMARK MODE!!! ----------------------------------------; 
;			
;			msign esi
;			msign esi
;			msign esi
;			counter_begin	1,HIGH_PRIORITY_CLASS
;			
;			push 	lpszFile
;			call 	CheckWithSiaExOld
;			
;			counter_end
;			mov 	eax,eax
;			mov 	eax,eax
;			
;			counter_begin	1,HIGH_PRIORITY_CLASS
;			
;			push 	lpszFile
;			call 	CheckWithSiaEx
;			
;			counter_end
;			mov 	eax,eax
;			mov 	eax,eax
;			
;			;-------------------------------------- END OF BENCHMARK ----------------------------------------;
			push 	lpszFile
			call 	CheckWithSiaEx
			.if 	eax
				; ------- Virus detected!! ------- ;
				mov 	retv,eax
				mov 	esi,eax
				mov 	edi,lpTFI
				assume 	edi:ptr THREATFULLINFO
				assume 	esi:ptr SIAVDBv2
				
				m2m 	[edi].uVirusInfo.dwType,[esi].uVirusInfo.dwType
				m2m 	[edi].uVirusInfo.dwCleanable,[esi].uVirusInfo.dwCleanable
				m2m 	[edi].uVirusInfo.Risk,[esi].uVirusInfo.Risk
				lea		eax,[edi].szThreatName
				lea 	edx,[esi].szThreatName
				invoke 	lstrcpyn,eax,edx,30
				
				.if 	[gTFI.lpszInfo]
					m2m 	[edi].uVirusInfo.Description,[gTFI.lpszInfo]
				.else
					m2m 	[edi].uVirusInfo.Description,[esi].uVirusInfo.Description
				.endif
				
				mov 	[edi].lpszInfo,0
				assume 	esi:nothing
				assume 	edi:nothing
				
				mLog 	"detected by SIA engine"
				
				; ------- console log ------- ;
				mov 	ebx,AppendLogConsole
				lea 	eax,szThisFile
				scall 	ebx,eax
				scall 	ebx,lpszFile
				lea 	eax,szDetectedUsesL3
				scall	ebx,eax
			.else				
				mLog	"..nothing"
				mLog 	"-Try to check uses level 4 (ansavai)"
				; ------- Check With ANSAVAI ------- ;				; --------------------[ -= LEVEL 4 =- ]
				invoke 	CheckUsesAnsavai,lpszFile
				.if 	eax
					; ------- Virus detected!! ------- ;
					mov 	retv,eax
					mov 	esi,eax
					mov 	edi,lpTFI
					assume 	edi:ptr THREATFULLINFO
					assume 	esi:ptr ANSAVAIVDBv2
					
					mov 	[edi].uVirusInfo.dwType,VIRI_SUSPECTED
					mov 	[edi].uVirusInfo.dwCleanable,VIRI_F_UNCLEANABLE
					mov 	[edi].uVirusInfo.Risk,0
					lea		eax,[edi].szThreatName
					mov 	edx,retv
					invoke 	lstrcpyn,eax,edx,30
					m2m 	[edi].uVirusInfo.Description,0
					
					m2m 	[edi].lpszInfo,SuspectInfo 
					
					assume 	esi:nothing
					assume 	edi:nothing
					
					mLog 	"detected by ANSAVAI engine"
					
					; ------- console log ------- ;
					mov 	ebx,AppendLogConsole
					lea 	eax,szThisFile
					scall 	ebx,eax
					scall 	ebx,lpszFile
					lea 	eax,szDetectedUsesL4
					scall	ebx,eax 
				.endif
			.endif
		.endif
		
@nousesthis:
		
		.if 	retv
			mov 	esi,AppendLogConsole
			
			scall 	esi,reparg("This file detected :")
			scall 	esi,lpszFile
			
			invoke 	IsTrusted,[ScannableFileObject.lpVoidMem],[ScannableFileObject.fSize]
			.if 	eax
				mov 	retv,0
				scall 	esi,reparg("But image was trusted.")
			.endif
		.endif
		
		; ------- flush hFile, fMap & lpVoidMem ------- ;
		mLog 	"-closing scannable file"
		mLog 	lpszFile
		call 	CloseScanableFile
	.else
		; ------- Check for exclude file ------- ;
		movzx 	eax,[ScannableFileObject.FileType]
		.if 	ax != FILE_TYPE_EXCLUDE
			; ------- Cannot load file for check ------- ;
			.if 	SingleCheck && !InsideZip
				ViewError	hMainWnd,"Cannot open file, may used by another process?"
			.endif
			mov 	FileScanAborted,1
			mLog 	"-Cannot load file for check"
			mLog 	lpszFile
			mLog 	"..failed"
		.else
			mLog 	"-File skipped from check =" 
			mLog 	lpszFile
		.endif
	.endif

@endl:

	; ------- If threats detected then set all info about it ------- ;
	.if 	retv
		mov 	edi,lpTFI
		assume 	edi:ptr THREATFULLINFO
		
		mov 	esi,lstrcpy
		
		lea 	eax,[edi].szFilePath
		.if 	InsideZip
			scall 	esi,eax,ZipScanFormat
			mov 	eax,offset szInsideArc
			mov 	[edi].uVirusInfo.Description,eax
		.else
			scall 	esi,eax,lpszFile
		.endif
		
		invoke 	GetFileAttributes,lpszFile
		mov 	[edi].dwAttribute,eax
		assume 	edi:nothing
	.endif

	; ------- seh trap ------- ;
	SehTrap 	__ctf
		call 	CloseScanableFile
		ErrorDump 	"CheckThisFile",offset CheckThisFile,offset szEngineAsm
		mWriteError reparg("In Scanning file :")
		mWriteError	lpszFile
		mLog 	"some error occured"
	SehEnd		__ctf

	.if 	ZipScanFormat
		.if 	ZipScanFormat!=offset szErrMem
			vfree ZipScanFormat
		.endif
	.endif

	; ------- make sure is all memory to be fresh! ------- ;
	call 	CloseScanableFile

	mLog 	"CheckThisFile endp"

	mov 	eax,retv
	ret

CheckThisFile endp

align 16

