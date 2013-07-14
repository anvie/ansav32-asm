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


; ------- heuristic.asm ------- ;

.data?
	; ------- CRC 32 Table ------- ;
	crcTable    		dd 256 dup (?)
	
	SuspectedFlag		dd ?
	
	; ------- header ------- ;
	EPRva				dd ?
	EPRaw				dd ?
	NumOfSection		dd ?
	EPInSection			dd ?
	ResourceRootRaw		dd ?
	ResourceDirRaw		dd ?
	
	; ------- section ------- ;
	ResourceSectionVA	dd ?
	ResourceSectionSize	dd ?
	
	
	; ------- resource ------- ;
	HaveIcon			dd ?
	HaveXPManifest		dd ?
	HaveVersion			dd ?
	
	; ------- packer/protector ------- ;
	LikePackerMEW		dd ?
	LikePackerUPX		dd ?
	
	; ------- misc ------- ;
	ImageOverlays		dd ?
	ImageOverlaysSize	dd ?
	CodeSectionModifiable dd ?
	HaveJunkCode dd ?
	InvalidSectionName	dd ?
	
	SuspectInfo			dd ?
	
	RESOURCE_TABLE_DIRECTORY_ENTRY	struct
	        Table		IMAGE_RESOURCE_DIRECTORY <>
	        Directory	IMAGE_RESOURCE_DIRECTORY_ENTRY  <>
	RESOURCE_TABLE_DIRECTORY_ENTRY	ends

    ICON_GROUP	struct
            GroupNameDir	RESOURCE_TABLE_DIRECTORY_ENTRY  <>
            GroupLangDir	RESOURCE_TABLE_DIRECTORY_ENTRY <>  
            GroupData		IMAGE_RESOURCE_DATA_ENTRY <>               
            IconCount		dd ?
            NameDir			IMAGE_RESOURCE_DIRECTORY <>
            NameEntries		IMAGE_RESOURCE_DIRECTORY_ENTRY 32 dup (<>)  
            LangDirs		RESOURCE_TABLE_DIRECTORY_ENTRY 32 dup (<>)  
            DataEntries		IMAGE_RESOURCE_DATA_ENTRY 32 dup (<>)                       
    ICON_GROUP	ends
    
	ICON_DIRECTORY_ENTRY	struct
	        Wdth		db ?
	        Hght		db ?
	        ColorCount	db ?
	        Reserved	db ?
	        Planes		dw ?
	        BitCount	dw ?
	        BytesInRes1	dw ?
	        BytesInRes2	dw ?
	        ID			dw ?
	ICON_DIRECTORY_ENTRY	ends

	ICON_DIRECTORY	struct
	        Reserved		dw ?
	        ResType			dw ?
	        Count			dw ?
	        Entries			ICON_DIRECTORY_ENTRY 32 dup (<>)
	ICON_DIRECTORY	ends

.data
	BAD_DOS_STUB				equ 1
	BAD_PE_FORMAT				equ 2
	BAD_EP_SECTION				equ 4
	BAD_OVERLAYS				equ 8
	NO_RESOURCE					equ 16
	MEW_CHARACTERISTICS_L1		equ 32
	
	szHeuristic 				db "heuristic.asm",0
	szSuspHackedUPX				db "Suspected/Fake.UPX",0
	szSuspHackedUPX2			db "Suspected/Worm.bu01",0
	szSuspHackedUPX3			db "Suspected/Heur.bu.inf",0
	szBadUPXInfo				db "Bad UPX packer header, maybe hacked/modified/scrambled, take care!",0
	szBadUPXInfo2				db "Bad UPX header, maybe infected by unknown virus, take care!",0
	szSuspMew					db "Suspected/Worm.bm01",0
	szSuspFSG					db "Suspected/Worm.pf56",0
	szSuspUPACK					db "Suspected/UPCK",0
	szSuspCorrupt				db "Suspected/Cort.PE",0
	szSuspCorruptInfo			db "Bad PE format, resource corrupted, may hacked/modified/infected",0
	szSuspInfPE					db "Suspected/Infected.EXE",0
	szSuspInfPEInfo 			db "Bad entrypoint, may was infected by unknown virus.",0
.code

align 16

crcInit proc
	push esi
	push edi
	
	mov ecx, 255
_loop:
	mov edx, 8
	mov eax, ecx
_loop2:
	shr eax, 1
	jnc _cont2
	xor eax, 0EDB88320h
_cont2:
	sub edx, 1
	jnz _loop2
	
	mov crcTable[4*ecx], eax
	
	sub ecx, 1
	jnc _loop
	
	mov eax, 0
	pop edi
	pop esi
	ret
crcInit endp

align 16

crcCalc proc _data:dword, _length:dword
	push esi
	push edi
	
	mov esi, _data
	
	mov eax, 0FFFFFFFFh
	
	mov ecx, 0
_loop:
	movzx edx, byte ptr [esi+ecx]
	xor edx, eax
	and edx, 0FFh
	mov edx, crcTable[4*edx]
	
	shr eax, 8
	xor eax, edx
	
	add ecx, 1
	cmp ecx, _length
	jnz _loop
	
	xor eax, 0FFFFFFFFh
	pop edi
	pop esi
	ret
crcCalc endp

align 16

RoundSize 	proc uses edx ecx iSize:DWORD,iAlignment:DWORD

	; ------- seh installation ------- ;
	SehBegin 	_rs

	mov 	eax,iSize
	add 	eax,iAlignment
	dec 	eax
	xor 	edx,edx
	mov 	ecx,iAlignment
	div 	ecx
	imul	eax,ecx

	; ------- seh trapper ------- ;
	SehTrap 	_rs
	SehEnd		_rs

	ret

RoundSize endp

align 16

ImageWritable proc lpImage:DWORD,ImageSize:DWORD
	
	; ------- seh instalaltion ------- ;
	SehBegin 	_rs
	
	mov 	ecx,lpImage
	mov 	edx,ecx
	
	add 	ecx,ImageSize
	add 	edx,400h
	cmp 	edx,ecx
	jnb 	@F
		mov 	eax,lpImage
		add 	ax,03ch
		add 	ax,[eax]
		sub 	ax,03ch
		add 	eax,sizeof IMAGE_NT_HEADERS
		mov 	edx,[eax.IMAGE_SECTION_HEADER].Characteristics
		test 	edx,080000000h
		.if 	!zero?
			test 	edx,020000000h
			.if 	!zero?
				test 	edx,000000020h
				.if 	!zero?
					SehPop
					return_1
				.endif
			.endif
		.endif
	@@:
	
	; ------- seh trapper ------- ;
	SehTrap 	_rs
	SehEnd 		_rs
	return_0

ImageWritable endp

align 16

include 	inc/asmstub.asm
include 	inc/ade32.asm

align 16

; advanced heuristic advanced disassembler engine
CodeJunk? proc uses esi edi ebx lpImage:DWORD,iSize:DWORD,lpszFile:DWORD
	
	LOCAL 	mnemonix:WORD
	LOCAL 	jval,l_eip,len:DWORD
	LOCAL 	ade32_flagtable[512]:DWORD
	LOCAL 	disstc:disasm_struct
	LOCAL 	lBuff[10h]:BYTE
	
	; ------- seh instalaltion ------- ;
	SehBegin	__cj?
	
	mov 	esi,MyZeroMemory
	
	; ------- find fake code ------- ;
	lea 	eax,ade32_flagtable
	scall 	esi,eax,512
	
	lea 	eax,ade32_flagtable
	push 	eax
	call 	_ade32_init
	add 	esp,4	; <-- fix stack ;
	
	lea 	eax,disstc
	scall 	esi,eax,sizeof disasm_struct
	lea 	eax,lBuff
	scall 	esi,eax,10h
	
	mov 	sset8,0
	mov 	eset8,0
	
	mov 	jval,0
	
	mov 	eax,lpImage
	mov 	l_eip,eax
	@lp:
		; ------- 32 bit code ------- ;
		mov 	al,04h
		mov 	[disstc.disasm_defaddr],al
		mov 	al,04h
		mov 	[disstc.disasm_defdata],al
		
			lea 	eax,ade32_flagtable
		push 	eax 
			lea eax,disstc 	
		push 	eax
		push 	l_eip
		call 	_ade32_disasm
		add 	esp,4*3	; <-- fix stack ;
		.if 	!eax
			jmp 	@out
		.endif
		mov 	len,eax
		
		mov 	esi,l_eip; ------- 8 BITS OPCODE CMP ------- ;
		.if 	len==1
			.if 	!sset8
				mov 	al,byte ptr [esi]
				mov 	sset8,al
				mov 	eset8,0
			.else
				mov 	al,byte ptr [esi]
				mov 	eset8,al
			.endif
			.if 	sset8 && eset8; ------- sub 8 INC/DEC ------- ;
				mov 	al,x_INC+reg_EDI
				mov 	ah,x_DEC+reg_EDI
				mov 	ecx,8
				@@:
					dec 	al
					dec 	ah
					.if sset8==al && eset8==ah
						inc 	jval
						mov 	sset8,0
						jmp 	@8bitout
					.endif
				loop @B
			.endif
			.if 	sset8 ; ------- sub 8 PUSH/POP ------- ;
				mov 	ebx,l_eip
				inc 	ebx
				
					lea 	eax,ade32_flagtable
				push 	eax
					lea 	eax,disstc
				push 	eax
				push 	ebx
				call 	_ade32_disasm
				add 	esp,4*3	; <-- fix stack ;
				.if 	!eax
					jmp 	@skip8pushpop
				.endif
				
				mov 	edx,[disstc.disasm_flag]
				test 	edx,C_MODRM
				.if 	zero?
					jmp 	@skip8pushpop
				.endif
				
				align 4
				
				add 	ebx,eax
					lea 	eax,ade32_flagtable
				push 	eax
					lea 	eax,disstc
				push 	eax
				push 	ebx
				call 	_ade32_disasm
				add 	esp,4*3	; <-- fix stack ;
				.if 	!eax
					jmp 	@skip8pushpop
				.endif
				cmp 	eax,1
				ja		@skip8pushpop
				mov 	al,byte ptr [ebx]
				mov 	eset8,al
				
				mov 	al,x_PUSH+reg_EDI
				mov 	ah,x_POP+reg_EDI
				mov 	ecx,8
				@@:
					dec 	al
					dec 	ah
					.if sset8==al && eset8==ah
						add 	jval,2
						mov 	sset8,0
						mov 	l_eip,ebx	; <-- renew eip ;
						jmp 	@8bitout
					.endif
				loop @B
				jmp 	@8bitout
			.endif
@skip8pushpop:
			.if 	sset8 && eset8
				mov 	sset8,0
				mov 	len,0
			.endif
		.else
			mov 	sset8,0
		.endif
		@8bitout:
		
		mov 	eax,len
		add 	l_eip,eax
		
		mov 	ecx,lpImage
		add 	ecx,iSize
		cmp 	l_eip,ecx
		jnb 	@out
	jmp 	@lp
@out:

	;mov 	eax,jval
	.if 	jval>4
		mov 	eax,jval
	.else
		xor 	eax,eax
	.endif

	align 4

IFNDEF 	SERVICE
	msign esi
ENDIF
	.if 	!eax
		lea 	eax,ade32_flagtable
			push 	eax
		lea 	eax,disstc
			push 	eax
		mov 	ebx,lpImage
		
		inc 	ebx
			push 	ebx	; <-- cur eip ;
		call 	_ade32_disasm
		add 	esp,4*3	; <-- fix stack ;
		.if 	eax
			test 	[disstc.disasm_flag],C_MODRM
			.if 	!zero?
				
				lea 	ecx,[ebx+eax]
				push 	eax
					lea 	eax,ade32_flagtable
						push 	eax
					lea 	eax,disstc
						push 	eax
						push 	ecx
					call 	_ade32_disasm
					add 	esp,4*3	; <-- fix stack ;
					xchg 	ecx,eax
				pop 	eax
				
				.if 	ecx==1
					dec 	ebx	; <-- to first eip EP ;
					mov 	cl,byte ptr [ebx]
					mov 	sset8,cl
					
					mov 	al,byte ptr [ebx+eax+1]
					mov 	eset8,al				
					
					mov 	al,x_PUSH+reg_EDI+1
					mov 	ah,x_POP+reg_EDI+1
					mov 	ecx,8
					@@:
						dec 	al
						dec 	ah
						.if 	sset8==al && eset8==ah
							mov 	eax,MUTLAK_TERINFEKSI
							jmp 	@endl
						.endif
					loop 	@B
				.endif
			.endif
		.endif
	.endif

	align 4

	; check for bad maskPE NOEP; -------------- ;
	mov 	ebx,lpImage
	cmp 	byte ptr [ebx],0c3h
	je 		@endl_zero
	inc 	ebx
	lea 	esi,ade32_flagtable
		push 	esi
	lea 	edi,disstc
		push 	edi
	push 	ebx
	call 	_ade32_disasm
	add 	esp,4*3
	xor 	ecx,ecx ;set counter
	.if 	eax
		
		test 	[disstc.disasm_flag],C_MODRM
		.if 	zero?
			mov 	ecx,10
			.while 	ecx
				sub 	ecx,1
				inc 	ebx
				push 	esi
				push 	edi
				push 	ebx
				call 	_ade32_disasm
				add 	esp,4*3
				cmp 	al,1
				jnz 	@F
				cmp 	byte ptr [ebx],0c3h
				je 		@F
			.endw
			test 	ecx,ecx
			jnz		@F
				mov 	eax,MUTLAK_TERINFEKSI
				jmp 	@endl
			@@:
		.endif
	.endif
	
@endl_zero:
	xor 	eax,eax	; <-- NOTHING ;

@endl:

	; ------- seh trapper ------- ;
	SehTrap		__cj?
IFNDEF 	SERVICE
		ErrorDump	"CodeJunk?",offset CodeJunk?,"Heuristic.asm"
		mWriteError "In Scanning image file :"
		mWriteError lpszFile
ENDIF
	SehEnd		__cj?
	
	ret
CodeJunk? endp

align 16

InitHeuristic proc
	
	sub 	eax,eax
	
	mov 	SuspectedFlag,eax
	
	mov 	EPRva,eax
	mov 	EPRaw,eax
	mov 	NumOfSection,eax
	mov 	EPInSection,eax
	mov 	ResourceRootRaw,eax
	mov 	ResourceDirRaw,eax
	
	mov 	ResourceSectionVA,eax
	mov 	ResourceSectionSize,eax
	
	mov 	HaveIcon,eax
	mov 	HaveVersion,eax
	mov 	HaveXPManifest,eax
	
	mov 	LikePackerMEW,eax
	mov 	LikePackerUPX,eax
	
	mov 	ImageOverlays,eax
	mov 	ImageOverlaysSize,eax
	
	mov		CodeSectionModifiable,eax
	mov 	HaveJunkCode,eax
	mov 	InvalidSectionName,eax
	
	ret

InitHeuristic endp

align 16

.data
	szSality	db "Suspected/Sality.inf",0
.code

CheckPolyVirus proc uses edi esi ecx EPptr:DWORD,iSize:DWORD,lpszFile:DWORD
	
	; ------- seh installation ------- ;
	SehBegin __cpv
	
	; ------- bug fixed ------- ;
	cmp 	edi,[ScannableFileObject.lpVoidMem]
	jb 		@endl
	mov 	ecx,[ScannableFileObject.lpVoidMem]
	add 	ecx,[ScannableFileObject.fSize]
	cmp 	edi,ecx
	jnb 	@endl
	; -------------- ;
	
	lea 	esi,SalityData
	mov 	edi,EPptr
	
	cld
	mov 	ecx,SalitySize
	invoke 	MyCompareMem,edi,esi,SalitySize
	.if 	eax
		
		lea eax,szSality
		SehPop
		ret
	.endif
	
@endl:

	; ------- seh trapper ------- ;
	SehTrap 	__cpv
IFNDEF 	SERVICE
		ErrorDump 	"CheckPolyVirus",offset CheckPolyVirus,offset szHeuristic
ENDIF
	SehEnd 		__cpv
	
	xor 	eax,eax	; <-- NULL ;
	ret

CheckPolyVirus endp

Align 16

CheckUsesAnsavai proc uses esi edi ebx lpszFile:DWORD

	LOCAL 	iBase,NtHeader,SectionHeader,lImage,iSize:DWORD
	LOCAL 	lNameRVA,lSubEntryRVA,IconImage,IconImageSize:DWORD
	LOCAL 	MaxReadableImage:DWORD
	LOCAL 	tmp,tmp2:DWORD
	LOCAL 	lIconGroup:ICON_GROUP
	LOCAL 	retv:DWORD

	; ------- seh installation ------- ;
	SehBegin	__cuai

	
	xor 	eax,eax
	mov 	retv,eax
	mov 	SuspectInfo,eax
	call 	InitHeuristic
	
	
    ; ------- check for plain/code ------- ;
    cmp 	[ScannableFileObject.FileType],IMAGE_FILE_NEUTRAL
    .if 	zero?
    	invoke 	ScanPlainImage,[ScannableFileObject.lpVoidMem],[ScannableFileObject.fSize]
    	mov 	retv,eax
    	jmp 	@endl
    .endif
	
	xor 	eax,eax
	
    
	align 8
	; ------- check type ------- ;
	; only for executable file
	test 	[ScannableFileObject.FileType],IMAGE_FILE_DLL
	jz 		@F
		SehPop
		ret
	@@:
	test	[ScannableFileObject.FileType],IMAGE_FILE_EXE
	jnz 	@F
		SehPop
		ret
	@@:

	; ------- check max size ------- ;
	mov 	ecx,[ScannableFileObject.fSize]
	mov 	iSize,ecx
	cmp 	ecx,3000000
	jb		@F
		SehPop
		ret
	@@:

	align 16

	; --------------------[ -= BEGIN CHECK =- ]
	mov 	esi,[ScannableFileObject.lpVoidMem]
	mov 	iBase,esi
	
		; ------- max readable offset ------- ;
		mov 	eax,esi
		add 	eax,[ScannableFileObject.fSize]
		mov 	MaxReadableImage,eax
	
	; ------- check for bad DOS stub ------- ;
	mov 	eax,esi
	add 	eax,04Eh
	mov 	ecx,40
	
	align 16
	
	@getdstb:
			; ------- check error ------- ;
			mov		edx,MaxReadableImage
			add 	edx,4
			cmp 	eax,edx
			jb 		@F
				SehPop
				xor 	eax,eax
				ret
			@@:
		cmp 	dword ptr [eax],'sihT'
		je 		@F
		add 	eax,1
	loop 	@getdstb
	
	test 	ecx,ecx
	jnz		@F
		or 		SuspectedFlag,BAD_DOS_STUB
		jmp 	@cdostb_ok
	@@:
	
	mov 	ecx,dword ptr [eax]
	test 	ecx,ecx
	jnz 	@F
		or 		SuspectedFlag,BAD_DOS_STUB
		jmp 	@cdostb_ok
	@@:
	
	; check it uses CRC 32
	push 	40
	push 	eax
	call 	crcCalc

	cmp 	eax,0DAEFA4B7h ; standard DOS Stub
	jz		@cdostb_ok
		or 		SuspectedFlag,BAD_DOS_STUB
	
	align 16
@cdostb_ok:

	; ------- get NT Header ------- ;
	add		esi,03Ch
	add 	si,word ptr [esi]
	sub 	si,03Ch
 	mov 	NtHeader,esi
 	
	assume 	esi:ptr IMAGE_NT_HEADERS
	; ------- get needed value ------- ;
	m2m 	ResourceSectionVA,[esi].OptionalHeader.DataDirectory[sizeof IMAGE_DATA_DIRECTORY +8].VirtualAddress
	m2m 	ResourceSectionSize,[esi].OptionalHeader.DataDirectory[sizeof IMAGE_DATA_DIRECTORY +8].isize

	; ------- get entry point ------- ;
	mov 	eax,[esi].OptionalHeader.AddressOfEntryPoint
	mov 	EPRva,eax
	invoke 	Rva2Raw,iBase,eax
	test 	eax,eax
	jnz		@F
		SehPop
		ret
	@@:
	add 	eax,iBase
	mov 	EPRaw,eax
	
	align 16
	
	; ------- get num of section ------- ;
	movzx 	eax,[esi].FileHeader.NumberOfSections
	mov 	NumOfSection,eax
		
	invoke 	ImageWritable,iBase,iSize
	mov 	CodeSectionModifiable,eax
	
	; ------- check junk code in EP ------- ;
	mov 	edx,iBase
	mov 	ecx,EPRaw
	
	cmp 	ecx,edx
	jb 		@F
	
	add 	ecx,200h
	
	add 	edx,iSize
	cmp 	ecx,edx
	jnb 	@F
	

	invoke 	CodeJunk?,EPRaw,400h,lpszFile
	.if 	eax==MUTLAK_TERINFEKSI
		mov 	SuspectInfo,offset szSuspInfPEInfo
		mov 	retv,offset szSuspInfPE
		jmp 	@endl
	.endif
	mov 	HaveJunkCode,eax
	@@:
	
	; ------- check for poly virus ------- ;
	invoke 	CheckPolyVirus,EPRaw,[ScannableFileObject.fSize],lpszFile
	.if 	eax
		mov 	retv,eax
		mov 	SuspectInfo,reparg("May be infected by W32/sality.")
		jmp 	@endl
	.endif
	
	; check for MEW characteristics
	mov		eax,[esi].FileHeader.TimeDateStamp
	test 	eax,eax
	jnz 	@F
		mov 	LikePackerMEW,0
	@@:
	
	align 4
	
	; ------- get section for entrypoint ------- ;
	mov 	ebx,esi
	
	; ------- bug fixed for native subsystem ------- ;
	mov 	eax,sizeof 	IMAGE_NT_HEADERS
	sub 	eax,sizeof 	IMAGE_OPTIONAL_HEADER32
	movzx 	ecx,[esi].FileHeader.SizeOfOptionalHeader
	add 	eax,ecx
	
	add 	ebx,eax
	; -------------- ;
	
	mov 	[SectionHeader],ebx
	assume 	ebx:ptr IMAGE_SECTION_HEADER
	
	; get UPX characteristics
	cmp 	dword ptr [ebx],'0XPU'
	jne 	@F
		mov 	LikePackerUPX,1
	@@:
	
	mov 	eax,ebx
	add 	eax,sizeof IMAGE_SECTION_HEADER
	
	cmp 	dword ptr [eax],'1XPU'
	jne 	@F
		mov 	LikePackerUPX,1
	@@:
	
	; trap UPX hacked/modified/fake/scrambled (bad UPX stub)
	.if 	LikePackerUPX
		test 	SuspectedFlag,BAD_DOS_STUB
		jz		@F
			mov 	LikePackerUPX,2	; <-- escalate alarm ;
		@@:
	.endif
	
	; get section for ep
	invoke 	ImageRvaToSection,NtHeader,iBase,EPRva
	test 	eax,eax
	jnz 	@F
		or 		SuspectedFlag,BAD_PE_FORMAT
		or 		SuspectedFlag,BAD_EP_SECTION
		jmp 	@checkovl
	@@:
	
	; check the EP section is?
	push 	ebx
		mov 	edx,[eax+0Ch] ; VirtualAddress
		mov 	eax,ebx
		xor 	ebx,ebx
		mov 	ecx,NumOfSection
		@lp:
			add 	ebx,1
			cmp 	edx,dword ptr [eax+0Ch] ; <- by
			je		@F
			add 	eax,sizeof IMAGE_SECTION_HEADER
		loop 	@lp
		@@:
		mov 	EPInSection,ebx
		mov 	tmp,eax
		mov 	eax,ebx
	pop 	ebx
	
	cmp 	eax,NumOfSection
	.if 	zero?
		or 		SuspectedFlag,BAD_EP_SECTION
	.endif
	
	; ------- check for valid section name ------- ;
	invoke 	IsAscii,tmp
	RevEax
	mov 	InvalidSectionName,eax
	msign esi
	msign esi
	.if 	eax
		cmp 	NumOfSection,2 ; skip FSG
		je 		@F
		cmp 	NumOfSection,4 ; skip Orean WinLicense Protector
		.if 	zero?
			mov 	eax,[SectionHeader]
			cmp 	[eax.IMAGE_SECTION_HEADER.Characteristics],0C0000040h
			je		@F
		.endif
		test 	SuspectedFlag,BAD_EP_SECTION
		jz 		@F
			mov 	retv,offset szSuspInfPE
			mov 	SuspectInfo,reparg("Bad Entrypoint, located at last section with obfuscated code.")
			jmp 	@endl
		@@:
	.endif
	
	align 16
@checkovl:

	; ------- check overlays ------- ;
	; ebx
	mov 	ecx,NumOfSection
	mov 	tmp,0
	@lp2:
		invoke 	RoundSize,[ebx].SizeOfRawData,200h
		mov 	edx,[ebx].PointerToRawData
		add 	edx,[ebx].SizeOfRawData
		cmp 	edx,tmp
		jbe 	@F
			mov 	tmp,edx
		@@:
		add 	ebx,sizeof IMAGE_SECTION_HEADER
	loop 	@lp2

	cmp 	tmp,0
	je		@no_overlays
	
	align 4
	
	mov 	eax,tmp
	cmp 	eax,[ScannableFileObject.fSize]
	jnb 	@no_overlays
	
	; overlays detected!
	mov 	edx,tmp
	mov 	ImageOverlays,edx	
	;add 	edx,iBase
	sub 	edx,iBase
	mov 	ImageOverlaysSize,edx
		
		cmp 	edx,50000
		jnb 	@no_overlays
			or 		SuspectedFlag,BAD_OVERLAYS
			
	align 4	
@no_overlays:
	
	; ------- check resource ------- ;
	invoke 	Rva2Raw,iBase,ResourceSectionVA
	test 	eax,eax
	jz 		@no_resource

	add 	eax,iBase
	
	push 	eax
		; ------- check error ------- ;
		mov 	ecx,MaxReadableImage
		cmp 	eax,ecx
		jb		@F
			add 	esp,4
			jmp 	@no_resource
		@@:
	pop 	eax
	
	mov 	ResourceRootRaw,eax
	
	mov 	eax,ResourceSectionVA
	add 	eax,sizeof IMAGE_RESOURCE_DIRECTORY
	
	invoke 	Rva2Raw,iBase,eax
	test 	eax,eax
	jz 		@no_resource
	
	add 	eax,iBase
	mov 	ResourceDirRaw,eax
	
	mov 	esi,ResourceRootRaw
	assume 	esi:ptr IMAGE_RESOURCE_DIRECTORY
	mov 	edi,ResourceDirRaw
	assume 	edi:ptr IMAGE_RESOURCE_DIRECTORY_ENTRY
	movzx 	ecx,[esi].NumberOfIdEntries
	movzx 	eax,[esi].NumberOfNamedEntries
	add 	ecx,eax
	

	test 	ecx,ecx
	jz 		@no_resource
	@lp3:
		push 	ecx
		; ------- icon ------- ;
		cmp 	HaveIcon,0
		jne 	@F
			cmp 	word ptr [edi].Name1,RT_GROUP_ICON
			jne 	@F
				mov 	eax,dword ptr [edi+04h]
				and 	eax,7FFFFFFFh
				add 	eax,ResourceSectionVA
				invoke 	Rva2Raw,iBase,eax
				test 	eax,eax
				jz 		@F
				
					add 	esp,4
					add 	eax,iBase
					
					; ------- bugfixed ------- ;
						mov ecx,iBase
						add ecx,iSize
						cmp eax,ecx
						ja  @F
					; -------------- ;
					
					mov 	HaveIcon,eax
					jmp 	@crsrc_ok
					nop
					nop
		@@: ; -------------- ;
		
		add 	edi,sizeof IMAGE_RESOURCE_DIRECTORY_ENTRY	; <-- next resource dir entry ;
		
		; ------- bugfixed ------- ;
			mov edx,iBase
			add edx,iSize
			cmp edi,edx
			jb  @F
				add 	esp,4
				jmp 	@crsrc_ok
				nop
				nop
			@@:
		; -------------- ;
		
		pop 	ecx
	loop 	@lp3
	
@crsrc_ok:

IFNDEF 	SERVICE
	msign 	esi
ENDIF
	; ------- check for resource icon ------- ;
	; kick indonesian malware!
	cmp 	HaveIcon,0
	je		@no_resource
		
		mov 	esi,HaveIcon
		
		mov 	ebx,esi
		assume 	ebx:ptr IMAGE_RESOURCE_DIRECTORY_ENTRY
		
		m2m 	lSubEntryRVA,dword ptr [ebx+14h]
		and 	lSubEntryRVA,7FFFFFFFh
		
		mov 	ecx,lSubEntryRVA
		add 	ecx,ResourceSectionVA
		invoke 	Rva2Raw,iBase,ecx
		; language entry
		
		mov 	edi,eax
		add 	edi,iBase
		
		; ------- bug fixed ------- ;
		mov 	eax,iBase
		add 	eax,iSize
		cmp 	edi,eax
		jnb 	@no_resource
		; -------------- ;
		
		mov 	ecx,dword ptr [edi+014h]
		and 	ecx,7FFFFFFFh
		mov 	eax,ResourceSectionVA
		add 	eax,ecx
		invoke 	Rva2Raw,iBase,eax
		add 	eax,iBase
		
		assume 	esi:ptr IMAGE_RESOURCE_DATA_ENTRY
		; -------------- ;
		mov 	esi,eax
		invoke	Rva2Raw,iBase,[esi].OffsetToData
		add 	eax,iBase
		mov 	edi,eax
		
		; ------- bug fixed ------- ;
		mov 	eax,iBase
		add 	eax,iSize
		cmp 	edi,eax
		jnb 	@no_resource
		; -------------- ;
		
		invoke 	MyZeroMemory,ADDR lIconGroup,sizeof ICON_GROUP
		mov 	eax,900000
		.if 	[ScannableFileObject.fSize]>eax && \
				!ImageOverlaysSize
			jmp 	@nolimage
			nop
			nop
		.endif
		
		invoke 	LoadLibraryEx,lpszFile,[ScannableFileObject.hFile],LOAD_LIBRARY_AS_DATAFILE
		test 	eax,eax
		jz 		@nolimage
		mov 	lImage,eax
		
		
		assume 	edi:ptr ICON_DIRECTORY
		movzx 	eax,word ptr [edi+04h]		; <-- Icon count member ;
		mov 	tmp,eax
		mov 	[lIconGroup.IconCount],eax
		mov 	[lIconGroup.NameDir.NumberOfIdEntries],ax
		
		xor 	ebx,ebx
		mov 	ecx,eax
		@lp4:
			push 	ecx
			
			mov 	eax,sizeof ICON_DIRECTORY_ENTRY
			mul 	ebx
			lea 	ecx,[edi].Entries.ID
			mov 	edx,ecx
			add 	edx,eax
			
				; ------- check error ------- ;
				cmp 	edx,MaxReadableImage
				jb 		@F
					add 	esp,4
					jmp 	@lp4_end
					nop
					nop
				@@:
			
			
			mov 	eax,eax
			movzx 	edx,word	ptr [edx]
			invoke 	FindResource,lImage,edx,RT_ICON
			.if 	eax
				invoke 	LoadResource,lImage,eax
				mov 	IconImage,eax
				
				; ------- reset error index ------- ;
				push	eax
					push 	0
					call 	SetLastError
				pop 	eax
				
				invoke 	LockResource,eax
				invoke 	SizeofResource,lImage,IconImage
				mov 	IconImageSize,eax
				
				; ------- check error ------- ;
				call 	GetLastError
				cmp 	eax,ERROR_RESOURCE_DATA_NOT_FOUND
				.if 	eax
					pop 	ecx
					
					test 	SuspectedFlag,BAD_DOS_STUB
					.if 	!zero?
						.if 	ecx == tmp && CodeSectionModifiable
							invoke 	FreeLibrary,lImage
							SehPop
							lea 	eax,szSuspCorruptInfo
							mov 	SuspectInfo,eax
							lea 	eax,szSuspCorrupt
							ret
						.endif
					.endif
					jmp 	@lp4_end
					nop
					nop
				.endif
				
				
				; ------- check it ------- ;
				lea 	esi,ANSAVAIVDBV2DATA
				
				@lp5:
					mov 	eax,esi
					mov 	ecx,[eax.ANSAVAIVDBv2].dwDataSize		; <-- data Image size ;
					
						; ------- filter size ------- ;
						movzx 	edx,word ptr [eax.ANSAVAIVDBv2].iSize
						cmp 	edx,IconImageSize
						jne 	@nx
					
					mov 	eax,[eax.ANSAVAIVDBv2].lpData
					
						; ------- check error ------- ;
						mov 	edx,MaxReadableImage
						add 	ecx,iBase
						cmp 	ecx,edx 
						jnb		@nx
					
					mov 	edx,IconImage
					add 	edx,20h
					
					align 16
					sub 	ecx,iBase
					
					; ------- get first unblank byte ------- ;		
					push 	esi
					push 	edi
					push 	ecx
					push 	eax
						cld
						mov 	ecx,IconImageSize
						mov 	eax,ecx
						
						push 	edx
							mul 	ecx
							xchg 	eax,ecx
							sub 	ecx,20h
						pop 	edx
						
						mov 	edi,edx
						xor 	al,al
						repe	scasb
						.if 	!ecx
							pop 	eax
							pop 	ecx
							pop 	edi
							pop 	esi
							jmp 	@nx
							nop
							nop
						.endif
						mov 	edx,edi		; <-- begin offset to compare ;
						dec 	edx
					pop 	eax
					pop 	ecx
					pop 	edi
					pop 	esi
					
					invoke 	MyCompareMem,edx,eax,ecx		; <-- compare it ;
					.if 	eax
						add 	esp,4	; <-- fix stack ;
						invoke 	FreeLibrary,lImage
						SehPop		; <-- main ;
						mov 	eax,[esi.ANSAVAIVDBv2].lpszInfo ; dword ptr [esi+30]
						test 	eax,eax
						jz 		@F
							mov 	SuspectInfo,eax
						@@:
						mov 	eax,esi
						ret
					.endif
					
					@nx:
					
					mov 	eax,[esi.ANSAVAIVDBv2].dwDataSize ; dword ptr [esi+30+8] ; ansavai size
					add 	eax,sizeof ANSAVAIVDBv2
					add 	esi,eax
					cmp 	byte ptr [esi],0
				jne		@lp5
				
				
			.endif
			
			add 	ebx,1
			pop 	ecx
			sub 	ecx,1
			jecxz 	@lp4_end
		jmp 	@lp4
		nop
		nop
@lp4_end:
		invoke 	FreeLibrary,lImage
@nolimage:
	jmp 	@F
	nop
	nop
@no_resource:
		or 		SuspectedFlag,NO_RESOURCE
	@@:
	
	align 16
	; ------- check for packer/protector ------- ;
	; blacklist some bad packer.
	mov 	eax,PackerIs
	.if 	eax
		.if 	eax == PACKER_MEW && ScanLevel>2 ; // 3
			lea 	eax,szSuspMew
			mov 	retv,eax
			jmp 	@endl
			nop
			nop
		.elseif 	eax == PACKER_UPX
			.if 	!LikePackerUPX && ScanLevel>2 ; // 3
				
				; ------- check again for section name ------- ;
				mov 	eax,[SectionHeader]
				cmp 	dword ptr [eax],'xet.'
				jne 	@F
					add 	eax,sizeof IMAGE_SECTION_HEADER
					cmp 	dword ptr [eax],'tad.'
					jne 	@F
						jmp 	@n_bu
				@@:
				cmp 	dword ptr [eax],'edoc'
				je 		@n_bu
				cmp 	dword ptr [eax],'txet'
				je 		@n_bu
				
				cmp 	dword ptr [eax],0
				jne 	@F
					test 	SuspectedFlag,BAD_DOS_STUB
					jz		@n_bu
				@@:
				
				lea 	eax,szSuspHackedUPX2
				mov 	retv,eax
				jmp 	@endl
				nop
				nop
			.endif
			@n_bu:
			
		.elseif 	eax == PACKER_WINUPACK && ScanLevel>2 ; // 3
			lea 	eax,szSuspUPACK
			mov 	retv,eax
			jmp 	@endl
			nop
			nop
		.elseif 	eax == PACKER_TELOCK && ScanLevel>2 ; // 3
			.if 	!HaveXPManifest && ImageOverlaysSize
				mov 	eax,reparg("Suspected/worm.te.ovl")
				mov 	retv,eax
				jmp 	@endl
				nop
				nop
			.endif
			
		.elseif 	eax == PACKER_PEC2
			
			mov 	eax,[SectionHeader]
			lea 	eax,[eax+018h]
			mov 	edx,[eax]
			cmp 	edx,'ASNA'
			jne 	@F
			mov 	al,byte ptr [eax+4]
			cmp 	al,'V'
			jne 	@F
				
				mov 	eax,reparg("Suspected/Moontox")
				mov 	retv,eax
				jmp 	@endl
				nop
				nop
			@@:
			
		.else
			align 16	; ------- check bad UPX ------- ;
			.if 	LikePackerUPX && NumOfSection > 3 && ScanLevel>2 ; // 3
				lea 	eax,szBadUPXInfo2
				mov 	SuspectInfo,eax
				lea 	eax,szSuspHackedUPX3
				mov 	retv,eax
				jmp 	@endl
				nop
				nop
			.elseif 	LikePackerUPX == 2 && ScanLevel>2 ; // 3
				test 	[SuspectedFlag],BAD_OVERLAYS
				.if 	!zero?
					lea 	eax,szBadUPXInfo2
					mov 	SuspectInfo,eax
					lea 	eax,szSuspHackedUPX3
					mov 	retv,eax
					jmp 	@endl
					nop
					nop
				.endif
			.elseif 	CodeSectionModifiable && HaveJunkCode && !HaveXPManifest && ScanLevel>2 ; // 3
					
					; kick polymorphic malware
					mov 	eax,reparg("Have bad code stub like encrypted or polymorphic code.")
					mov 	SuspectInfo,eax
					mov 	eax,reparg("Suspected/Morph.cod")
					mov 	retv,eax
					jmp 	@endl
					nop
					nop			
			.endif
		.endif
	.endif
	
	assume 	esi:nothing
	assume 	edi:nothing
	assume 	ebx:nothing
	
@endl:
	
	; ------- seh trap ------- ;
	SehTrap 	__cuai
IFNDEF 	SERVICE
		ErrorDump		"CheckUsesAnsavai",offset CheckUsesAnsavai,"Heuristic.asm"
		mWriteError		reparg("In Scanning file :")
		mWriteError		lpszFile
ENDIF
	SehEnd		__cuai
	
	mov 	eax,retv
	ret

CheckUsesAnsavai endp

align 16






