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

; ------- utils_ansav.asm ------- ;
; utils for Ansav 

; ------- Prototype ------- ;

include 	inc\debug.asm
.data? ;----------------------------------|			; --------------------[ -= LUID - TOKEN STUB =- ]
    LUIDCUST STRUCT                      ;|
        usedpart dd ?                    ;|
        ignorehigh32bitpart dd ?         ;|
    LUIDCUST ENDS

    TOKEN_PRIVS STRUCT
        privilegecount dd ?
        theluid     LUIDCUST <>
        attributes  dd ?
    TOKEN_PRIVS ENDS                     ;|
                                         ;|
    advapif dd 5 dup (?)                 ;|
      ;-----------------------------------|
.data
	szUtilsasm db "utils_ansav.asm",0
	szAdjustPrivErrorF	db "Error code 0x%p, cannot adjust privilege for power off computer.",0
	szFileDoesnEx db "File doesn't exist any more",0
.code
; ------- Arrayer Load Api functions ------- ;
_LoadApi proc uses esi libname:DWORD, szfunc:DWORD, hfunc:DWORD


    invoke  LoadLibrary,libname
    mov     ebx,eax
    or      eax,eax
    jz      @load_api_err
    mov     eax,hfunc
    mov     eax,dword ptr [eax]
    test    eax,eax
    jnz     @load_api_err   
    invoke  GetProcAddress,ebx,szfunc
    or      eax,eax
    jz      @load_api_err
    mov     esi,hfunc
    mov     dword ptr [esi],eax
    mov     eax,ebx
@load_api_err:
    ret
_LoadApi endp

align 16

; ------- Get Win Version ------- ;
IsNT proc
	
	call 	GetVersion
	not 	eax
	shr 	eax,1Fh
	ret

IsNT endp

align 16

; ------- Escalate Privileges in NT/2K/XP ------- ;
SetPrivileges proc uses edi esi
    LOCAL hdlProcessHandle:DWORD
    LOCAL hdlTokenHandle:DWORD
    LOCAL tmpLuid:LUIDCUST
    LOCAL tkp:TOKEN_PRIVS
    LOCAL tkp2:TOKEN_PRIVS
    LOCAL lBuffd:DWORD
    LOCAL lBuffb:DWORD
    LOCAL ptBuff:DWORD
    LOCAL macl:DWORD
    
	mLog  "Try to escalate privileges.."


    lea     esi,advapif
    lea     edi,szAdvapi
    add     edi,13
 @lod:
    invoke  _LoadApi,offset szAdvapi,edi,esi
    add     esi,4
    NextArray @lod

    mov     ecx,dword ptr[esi-5*4]
	.if 	!ecx
		mLog 	"..Failed"
		jmp 	@endl
	.endif

    invoke  LocalAlloc,LPTR,sizeof ACL
    mov     macl,eax
    push    2
    push    sizeof ACL
    push    eax
    lea     esi,advapif
    call    dword ptr [esi+1*4] ; InitializeACL

    call    GetCurrentProcess
    mov     hdlProcessHandle,eax

    push    0
    push    macl
    push    0
    push    0
    push    4
    push    6
    push    eax
    call    dword ptr [esi+4*4]     ; SetSecurityInfo

    invoke  LocalAlloc,LPTR,32
    mov     ptBuff,eax
    mov     byte ptr [eax],0

    lea     eax,hdlTokenHandle
    push    eax
    push    40
    push    hdlProcessHandle
    call    dword ptr [esi+3*4]  ; OpenProcessToken

    lea     eax,tmpLuid
    push    eax
    lea     eax,szSDP
    push    eax
    push    ptBuff
    call    dword ptr [esi+2*4] ; LookupPrivilegeValueA
    
    lea     eax,tmpLuid

    mov     ecx,(LUIDCUST PTR [eax]).usedpart
    mov     edx,(LUIDCUST PTR [eax]).ignorehigh32bitpart

    lea     eax,tkp

    mov     (TOKEN_PRIVS PTR [eax]).privilegecount,1
    mov     (TOKEN_PRIVS PTR [eax]).theluid.usedpart, ecx
    mov     (TOKEN_PRIVS PTR [eax]).theluid.ignorehigh32bitpart,edx
    mov     (TOKEN_PRIVS PTR [eax]).attributes,2

    lea     eax,lBuffd
    push    eax
    lea     eax,tkp2
    push    eax
    mov     ecx,sizeof tkp2
    push    ecx
    lea     eax,tkp
    push    eax
    push    0
    push    hdlTokenHandle
    call    dword ptr [esi+0*4] ; AdjustTokenPrivileges
    .if 	eax
    	mLog "..Success"
    .endif
    
    invoke  LocalFree,macl
    invoke  LocalFree,ptBuff
	
@endl:
    ret
SetPrivileges endp

align 16

SetToken proc 			; --------------------[ -= Need admin right =- ]
	
	.if 	WinVerNT
		; ------- If NT/2K or XP ------- ;
		; then escalate privileges uses AdjustTokenPrivileges
		call 	SetPrivileges
	.else
		
	.endif
	ret

SetToken endp

align 16

; ------- Get all process count ------- ;
; return value = process count
GetNumAllProcesses proc

	LOCAL 	hSnap,ProcessCount:DWORD
	LOCAL 	lpe:PROCESSENTRY32
	LOCAL 	retv:DWORD
	
	; ------- seh installation ------- ;
	SehBegin 	__gnap
	
	mLog 	"GetnumAllProcesses::"
	
	invoke 	MyZeroMemory,ADDR lpe,sizeof 	PROCESSENTRY32
	mov 	retv,0
	mov 	ProcessCount,0
	
	invoke 	CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS,0
	.if 	eax!=0 && eax!=-1
		mov 	hSnap,eax
		
		mov 	[lpe.dwSize], sizeof PROCESSENTRY32
		invoke 	Process32First,hSnap,ADDR lpe
		.if 	eax
			.while 	eax
				inc 	ProcessCount
				
				invoke 	Process32Next,hSnap,ADDR lpe
			.endw
			m2m 	retv,ProcessCount
		.endif
		
		invoke 	CloseHandle,hSnap
		
	.endif
	
	; ------- seh trap ------- ;
	SehTrap 	__gnap
		ErrorDump 	"GetNumAllProcesses",offset GetNumAllProcesses,"utils_ansav.asm"
	SehEnd 		__gnap
	
	mov 	eax,retv
	ret

GetNumAllProcesses endp

align 16

; ------- GetProcessPath uses PID ------- ;
GetProcessPath proc 	lpszBuffer:DWORD, cbSize:DWORD, dwPID:DWORD
	
	LOCAL 	hSnap:DWORD
	LOCAL 	mde:MODULEENTRY32
	LOCAL 	retv:DWORD
	
	mLog 	"GetProcessPath::"
	
	; -------  SEH Installation ------- ;
	SehBegin	__gpp
	
	invoke 	MyZeroMemory,ADDR mde,sizeof MODULEENTRY32
	mov 	retv,0
	
	invoke 	CreateToolhelp32Snapshot,TH32CS_SNAPMODULE,dwPID
	.if 	eax!=-1 && eax!=0
		mov 	hSnap,eax
		
		mov 	mde.dwSize,sizeof MODULEENTRY32
		
		invoke 	Module32First,hSnap,ADDR mde
		.if 	eax
			.while 	eax
				
				mov 	eax,mde.th32ProcessID
				cmp	 	eax,dwPID
				jne 	@mnext
				cmp 	eax,4
				je 		@mnext
					
					; ------- Get path ------- ;
					invoke 	MyZeroMemory,lpszBuffer,cbSize
					lea 	eax,mde.szExePath
					invoke 	lstrcpyn,lpszBuffer,eax,cbSize
					mov 	eax,lpszBuffer
					cmp 	byte ptr [eax],0
					je 		@endl
					mov 	retv,eax
					jmp 	@endl
				
				@mnext:
				invoke 	Module32Next,hSnap,ADDR mde
			.endw
		.endif
		@endl:
		invoke 	CloseHandle,hSnap
	.endif	

	; ------- Seh handle for GetProcessPath ------- ;
	SehTrap		__gpp
		ErrorDump	"GetProcessPath",offset GetProcessPath,"utils_asnsav.asm"
	SehEnd		__gpp
	
	.if 	retv
		invoke 	SetLastError,0
	.endif
	mov 	eax,retv
	ret

GetProcessPath endp

align 16

; ------- Convert Precent ------- ;
PercentThis proc uses edx ecx lValue:DWORD,lMax:DWORD
	
	; ------- seh installation ------- ;
	SehBegin 	_pt
	
	mov 	ecx,lMax
	jecxz	@F
	mov 	eax,100
	imul 	eax,lValue
	xor 	edx,edx
	div 	ecx
	SehPop 
	ret
	@@:
	
	; ------- seh trapper ------- ;
	SehTrap		_pt
		ErrorDump 	"PercentThis",offset PercentThis,offset szUtilsasm
	SehEnd 		_pt 	
	
	xor 	eax,eax
	ret

PercentThis endp

align 16

; ------- For detecting file exists ------- ;
FileExist proc lpszFile:DWORD

    invoke 	CreateFile,lpszFile,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
    inc eax
    .if eax
        dec eax
        push eax
        call CloseHandle
        inc eax
        ret
    .endif

    xor eax,eax
    ret
FileExist endp

align 16

; ------- Quick get file size ------- ;
QGetFileSize proc lpszFile:DWORD

	LOCAL 	hFile:DWORD
	LOCAL 	retv:DWORD
	
	mov 	retv,0
	invoke 	CreateFile,lpszFile,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
	.if 	eax != -1
		mov 	hFile,eax
		
		invoke 	GetFileSize,eax,0
		mov 	retv,eax
		
		invoke 	CloseHandle,hFile
	.endif
	
	mov 	eax,retv
	ret

QGetFileSize endp

align 16

; ------- My Copy mem ------- ;
MyCopyMem	proc lpDest:DWORD,lpSrc:DWORD,cchMax:DWORD

	push 	esi
	push 	edi
	push 	ecx

	mov 	ecx,cchMax
	mov 	edx,ecx
	and 	edx,3
	shr 	ecx,2
	mov 	edi,lpDest
	mov 	esi,lpSrc
	rep		movsd
	or 		ecx,edx
	jz 		@F
	rep		movsb
	@@:
	
	pop 	ecx
	pop 	edi
	pop 	esi
	ret

MyCopyMem endp

align 16

; i'm forget where i'm got this routine, but is realy faster than standard cmpmem Win have
; ------- new proc ------- ;
MyCompareMem proc lpTarget:DWORD,lpCompareWith:DWORD,cchMax:DWORD
	
	
            mov     eax, lpTarget      ; eax = pointer to left operand
            mov     edx, lpCompareWith      ; edx = pointer to right operand
            mov     ecx, cchMax     ; ecx = count
            cmp     ecx, 4              ; jmp if more than 4 bytes to compare
            jg      fixalign            ; otherwise forget about alignment and just compare the 1-4 bytes
            cmp     ecx, 1
            jl      same                ; equal if zero bytes or fewer bytes to compare
            neg     ecx                 ; ecx = bytes past the end (0-3 in bits 0,1)
            mov     eax, [eax]          ; compare one dword (i.e. 1-4 bytes of it)
            shl     ecx, 3              ; ecx = top-end bits to ignore (0, 8, 16 or 24 in low5 bits)
            xor     eax, [edx]          ; compare entire dword
            shl     eax, cl             ; lose unwanted upper bytes and test what's left
            sub     eax, 1              ; carry => equal
            sbb     eax, eax            ; eax = 0 or -1
            neg     eax                 ; return 1/0 for equal/not equal
            
            ret		3*4
                
            align   8
fixalign:   push     ebx                ; save ebx and edi for use below
            push    edi 
            mov     ebx, eax            ; ebx = points to left operand
            sub      edx, eax           ; edx = address of right operand relative to left operand
            jz      equal               ; return equal for equal addresses
            test    ebx, 3              ; jmp if ebx already aligned
            jz      next4

            mov     edi, ebx                ; compute leading bytes to ignore (1-3)
            and     ebx, not 3              ; chop ebx down to dword
            and     edi, 3                  ; edi = bytes to ignore
            mov     eax, [ebx]              ; compare left and right dwords
            lea     ecx, [edi * 8]          ; ecx = low-end bits to ignore (8, 16 or 24)
            xor     eax, [ebx + edx]        ; xor leaves comparison bits in eax
            add     ebx, 4                  ; advance dword address (for both operands)
            shr     eax, cl                 ; lose the low cl bits from eax (sign-extension ok here)
            mov     ecx, cchMax         ; ecx = original count
            jnz     noteq                   ; if non-zero then not-equal
            lea     ecx, [ecx + edi - 4]    ; ecx = remaining bytes to compare

            align   8
next4:      test    ebx, 4                  ; check for the odd dword
            jz      next8                   ; jmp ahead if none
            mov     eax, [ebx]              ; compare left and right dwords
            xor     eax, [ebx + edx]        ; (don't use a cmp here, only use an xor)
            jne     tailchk4                ; jmp to tailchk when not equal
            add     ebx, 4                  ; now we have 8-byte alignment
            sub     ecx, 4
            jbe     equal                   ; equal, if the count runs out

            align   8
next8:      mov     eax, [ebx]              ; load 8 bytes at a time
            mov     edi, [ebx + 4]
            xor     eax, [ebx + edx]        ; (don't use a cmp here, only use an xor)
            jne     tailchk4                ; jmp to tailchk when not equal
            xor     edi, [ebx + edx + 4]
            jne     tailchk8                ; jmp to tailchk when not equal
            add     ebx, 8
            sub     ecx, 8
            ja      next8                   ; repeat while 1 or more bytes remain

equal:      pop     edi
            pop     ebx
same:       mov     eax, 1          ; return equal
            ret		3*4

noteq:      pop    edi
            pop     ebx
            mov     eax, 0          ; return not equal
            ret		3*4

            ; evaluate a not-equal result
tailchk8:   sub     ecx, 4          ; account for the first of two dwords
            jle     equal           ; equal if search already ended on the 1st dword match
            mov     eax, edi        ; move comparison bits to eax for examination
tailchk4:   sub     ecx, 4          ; account for the 2nd dword
            jge     noteq           ; not-equal if not off the end
            neg     ecx             ; ecx = bytes too far (1-3)
            shl     ecx, 3          ; ecx = number upper eax comparison bits to lose (8-16-24)
            pop     edi
            shl     eax, cl         ; lose unwanted comparison bytes and test what's left
            pop     ebx
            sub     eax, 1          ; carry => zeros => equality
            sbb     eax, eax        ; eax = 0 or -1
            neg     eax             ; return 1/0 for equal/not equal
            ret		3*4
	ret

MyCompareMem endp
; ------- new proc ------- ;

align 16

; ------- get dir path only without file ------- ;
OnlyPathDir 	proc uses edi lpszPathFile:DWORD	; ------- IN OUT ------- ;

	; ------- seh installation ------- ;
	SehBegin 	_opd

	mov 	edi,lpszPathFile
	invoke	IsObjectInsideArc?,edi
	.if 	eax
		cld
		or ecx,MAX_PATH
		mov al,':'
		repne scasb
		repne scasb
		dec edi
		mov byte ptr [edi],0
	.endif 	
	mov 	edi,lpszPathFile
	
	strlen	edi
	
	or eax,eax
	jz 	@endl
		add 	edi,eax
		mov 	ecx,eax
		@@:
			dec 	edi
			cmp 	byte ptr [edi],05ch	; '\'
			je 		@F
		Loop	@B
		jmp 	@endl
		@@:
		mov 	word ptr [edi],0000h
	
@endl:

	; ------- seh trapper ------- ;
	SehTrap 	_opd
		ErrorDump 	"OnlyPathDir",offset OnlyPathDir,offset szUtilsasm
	SehEnd 		_opd

	ret


OnlyPathDir endp

align 16

; ------- Get file name only from real path ------- ;
OnlyFileName 	proc  uses edi lpBuffer:DWORD, lpszPathFile:DWORD
	
	; ------- seh installation ------- ;
	SehBegin 	__ofn
	
	mov 	edi,lpszPathFile
	
	strlen edi 
	
	add 	edi,eax
	mov 	ecx,eax
	@lp:
		cmp 	byte ptr [edi],05ch ; '\'
		je		@F
		dec 	edi
	Loop 	@lp
	jmp 	@lend
	@@:
	inc 	edi
	
	strlen  edi
	
	inc		eax
	invoke 	lstrcpyn,lpBuffer,edi,eax
@lend:

	; ------- seh trapper ------- ;
	SehTrap 	__ofn
		ErrorDump 	"OnlyFileName",offset OnlyFileName,offset szUtilsasm
	SehEnd 		__ofn

	ret

OnlyFileName endp

align 16

; ------- Make path + '\' ------- ;
TruePath proc uses edi tText:DWORD

    mov 	edi,tText
    EndString 260

    cmp 	word ptr [edi-1],005ch
    je  	@the_end
    mov 	word ptr [edi],005ch
@the_end:
    ret
TruePath endp

align 4

TopNoTop proc uses esi ebx hWin:DWORD,IDctl:DWORD
	
	mov 	esi,SetWindowPos
	mov 	ebx,hWin
	invoke 	IsDlgButtonChecked,ebx,IDctl
	.if 	eax
		scall 	esi,ebx,HWND_TOPMOST,0,0,0,0,3
	.else
		scall 	esi,ebx,HWND_NOTOPMOST,0,0,0,0,3
	.endif
	ret

TopNoTop endp

align 16

; ------- BVI Stuff------- ;
InitBufferVirusInfo proc

	; ------- seh installation ------- ;
	SehBegin __ibvi

	invoke 	AppendLogConsole,reparg("Initalizing buffer for BVI...")
	.if 	pBufferVirusInfo
		jmp 	@sucks
	.endif
	mov 	pBufferVirusInfo,0
	mov 	BufferVirusInfoItemCount,0
	mov 	BufferVirusInfoSize,0
	; ------- allocate default TFI size = 2*sizeof TFI+1 ------- ;
	mov 	BufferVirusInfoSize,(sizeof THREATFULLINFO+1)
	valloc 	BufferVirusInfoSize
	.if 	eax
		mov 	pBufferVirusInfo,eax
		mov 	BufferVirusInfoItemCount,0
		jmp 	@sucks
	.endif
	
	; ------- seh trapper ------- ;
	SehTrap 	__ibvi
		ErrorDump	"InitBufferVirusInfo",offset InitBufferVirusInfo,offset szUtilsasm
	SehEnd		__ibvi
	
	invoke 	AppendLogConsole,offset szFailed
	SehPop
	ret
@sucks:
	invoke 	AppendLogConsole,ADDR szInitSuckses
	SehPop
	return_1

InitBufferVirusInfo endp

align 16

BufferVirusInfoInsert proc uses edi esi ecx lpTFI:DWORD

	LOCAL 	NewBufferVirusInfo:DWORD
	LOCAL 	NewBufferVirusInfoSize:DWORD
	
	; ------- seh installation ------- ;
	SehBegin 	__bvii
	
	.if 	!pBufferVirusInfo
		SehPop
		return_0
	.endif
	
	.if 	BufferVirusInfoItemCount == 0
		; ------- If 0 Only Store it ------- ;
		mov 	esi,lpTFI
		mov 	edi,pBufferVirusInfo
		
		invoke 	MyCopyMem,edi,esi,sizeof THREATFULLINFO
		
		inc 	BufferVirusInfoItemCount
		SehPop
		return_1
	.else
		; ------- Save old BVI ------- ;
		mov 	ecx,BufferVirusInfoSize
		add 	ecx,sizeof THREATFULLINFO
		valloc 	ecx
		.if 	eax
			
			mov 	NewBufferVirusInfo,eax
			
			; ------- Store old BVI to new BVI mem ------- ;
			cld
			mov 	esi,pBufferVirusInfo
			mov 	edi,eax
			
			invoke 	MyCopyMem,edi,esi,BufferVirusInfoSize
			
			; free old BVI mem
			vfree	pBufferVirusInfo
			
			; ------- Append new TFI ------- ;
			mov 	eax,BufferVirusInfoItemCount
			xor 	edx,edx
			mov 	ecx,sizeof THREATFULLINFO
			mul 	ecx
			
			mov 	edi,NewBufferVirusInfo
			add 	edi,eax
			mov 	esi,lpTFI
			
			invoke 	MyCopyMem,edi,esi,sizeof THREATFULLINFO
			
			; set new pBuffer void, count & size
			m2m 	pBufferVirusInfo,NewBufferVirusInfo
			inc 	BufferVirusInfoItemCount
			add 	BufferVirusInfoSize,sizeof THREATFULLINFO
			
		.endif
		
	.endif
	
	; ------- seh trapper ------- ;
	SehTrap 	__bvii
		ErrorDump 	"BufferVirusInfoInsert",offset BufferVirusInfoInsert,offset szUtilsasm
	SehEnd 		__bvii
	
	ret

BufferVirusInfoInsert endp

align 16

CloseBufferVirusInfo proc
	
	; ------- seh installation ------- ;
	SehBegin 	__cbvi
	
	mov 	eax,pBufferVirusInfo
	.if 	eax
		vfree 	eax
		invoke 	AppendLogConsole,offset szDone
		
		xor 	eax,eax
		mov 	pBufferVirusInfo,eax
	.endif

	; ------- seh trapper ------- ;
	SehTrap 	__cbvi
		ErrorDump 	"CloseBufferVirusInfo",offset CloseBufferVirusInfo,offset szUtilsasm
	SehEnd 		__cbvi	
	ret

CloseBufferVirusInfo endp

Align 16


MyZeroMemory proc lpszString:DWORD,cchMax:DWORD
	
	.if 	HaveMMX
		push 	esi
			mov 	esi,lpszString
			mov 	eax,cchMax
			call 	mzm
		pop 	esi
	.else
        PUSH 	EDI
        db 3eh
        MOV 	EDI,lpszString
        MOV 	ECX,cchMax
        db 3eh
        XOR 	EAX,EAX
        CLD
        MOV 	EDX,ECX
        db 3eh
        AND 	EDX,3
        SHR 	ECX,2
        REP 	STOSD
        db 3eh
        OR 		ECX,EDX
        JNZ 	@kill_remains_byte
        POP 	EDI
        RET

@kill_remains_byte:

        REP 	STOS BYTE PTR ES:[EDI]
        db 3eh
        POP 	EDI
        RET
	.endif
	
	ret

MyZeroMemory endp

align 16

; these routine bellow will be execute if ANSAV running under computer 
; with processor that have a MMX instruction capability
; running more faster than memset function on the C library
; i'm got this code from masm32 forum http://www.masm32.com
mzm proc
	
	push ebx									;; empiler ebx
		push ecx									;; empiler ecx

; premièrement on va s'assurer que la taille minimale est atteinte, sinon on va directement traiter les dwords
		xor ebx,ebx								;; effacer ebx (ca doit être fait ici, pour que tout fonctionne normalement)
		cmp eax,00000000000000000000000000001111b		;; comparer eax à 15
		jbe Label09								;; si c'est inférieur ou égal, aller Label09

; ici, on s'occupe de la partie non alignée
;
		mov ecx,esi								;; copier l'adresse de départ dans ecx
		and ecx,00000000000000000000000000001111b		;; enlever les OWORDs en ecx
		jz Label05								;; si ecx est égal à zéro (c'est déjà aligné), aller Label05
		mov ebx,00000000000000000000000000010000b		;; sinon, placer 16 (ben oui, ici il faut tenir compte du 0 qui ne sera pas traité) dans ebx
		sub ebx,ecx								;; enlever ecx à ebx
		sub eax,ebx								;; enlever ebx (la partie non alignée) à eax (la taille originelle)
; ici on traite les octets du début (on commence par les octets, pour bénéficier d'un meilleur alignement avec les dwords)
Label01:	mov ecx,ebx								;; placer la taille à copier dans ecx
		and ecx,00000000000000000000000000000011b		;; ne conserver que les bits octets en ecx
		jz Label03								;; si ecx est égal à 0, aller Label03
		add esi,ecx								;; on ajoute ecx à esi
		neg ecx									;; inverser ecx
Label02:	mov BYTE PTR [esi+ecx],0						;; placer 0 en esi+ecx
		inc ecx									;; on ajoute 1 à ecx (notre pas de boucle)
		jnz Label02								;; tant que ecx est différent de 0, aller Label02
; ici on traite les dwords du début
Label03:	mov ecx,ebx								;; placer la taille à copier dans ecx
		and ecx,00000000000000000000000000001100b		;; ne conserver que les bits dwords en ecx
		jz Label05								;; si ecx est égal à 0, aller Label05
		add esi,ecx								;; on ajoute ecx à esi
		neg ecx									;; inverser ecx
Label04:	mov DWORD PTR [esi+ecx],0					;; placer 0 en esi+ecx
		add ecx,4									;; on ajoute 4 à ecx (notre pas de boucle)
		jnz Label04								;; tant que ecx est différent de 0, aller Label04


;
; ici, c'est aligné alors on traite les 4x owords
;
Label05:	mov ecx,eax								;; placer la taille à copier dans ecx
		and ecx,11111111111111111111111111000000b		;; ne conserver que les bits 4x owords en ecx
		jz Label07								;; si ecx est égal à 0, aller Label07
		add esi,ecx								;; on ajoute ecx à esi
		neg ecx									;; inverser ecx
		nop										;; alignement nécessaire pour un meilleur rendement
		xorps XMM0,XMM0							;; effacer XMM0
Label06:	movaps OWORD PTR[esi+ecx],XMM0				;; placer 0 en esi+ecx
		movaps OWORD PTR[esi+ecx+16],XMM0				;; placer 0 en esi+ecx+16
		movaps OWORD PTR[esi+ecx+32],XMM0				;; placer 0 en esi+ecx+32
		movaps OWORD PTR[esi+ecx+48],XMM0				;; placer 0 en esi+ecx+48
		add ecx,64								;; on ajoute 64 à ecx (notre pas de boucle)
		jnz Label06								;; tant que ecx est différent de 0, aller Label06

; ici, on traite les owords
Label07:	mov ecx,eax								;; placer la taille à copier dans ecx
		and ecx,00000000000000000000000000110000b		;; ne conserver que les bits owords en ecx
		jz Label09								;; si ecx est égal à 0, aller Label09
		add esi,ecx								;; on ajoute ecx à esi
		neg ecx									;; inverser ecx
		xorps XMM0,XMM0							;; effacer XMM0
Label08:	movaps OWORD PTR[esi+ecx],XMM0				;; placer 0 en esi+ecx
		add ecx,16								;; on ajoute 16 à ecx (notre pas de boucle)
		jnz Label08								;; tant que ecx est différent de 0, aller Label08

; ici, on traite les dwords
Label09:	mov ecx,eax								;; placer la taille à copier dans ecx
		and ecx,00000000000000000000000000001100b		;; ne conserver que les bits dwords en ecx
		jz Label11								;; si ecx est égal à 0, aller Label11
		add esi,ecx								;; on ajoute ecx à esi
		neg ecx									;; inverser ecx
Label10:	mov DWORD PTR [esi+ecx],0					;; placer 0 en esi+ecx
		add ecx,4									;; on ajoute 4 à ecx (notre pas de boucle)
		jnz Label10								;; tant que ecx est différent de 0, aller Label10

; ici, on traite les octets
Label11:	mov ecx,eax								;; placer la taille à copier dans ecx
		and ecx,00000000000000000000000000000011b		;; ne conserver que les bits octets en ecx
		jz Label13								;; si ecx est égal à 0, aller Label13
		add esi,ecx								;; on ajoute ecx à esi
		neg ecx									;; inverser ecx
Label12:	mov BYTE PTR [esi+ecx],0						;; placer 0 en esi+ecx
		inc ecx									;; on ajoute 1 à ecx (notre pas de boucle)
		jnz Label12								;; tant que ecx est différent de 0, aller Label12

; enfin, on corrige les valeurs utilisées pour retrouver les valeurs originelles
Label13:	add eax,ebx								;; rajouter ebx à eax
		sub esi,eax								;; soustraire la taille à esi (pour retrouver l'adresse originelle)

		pop ecx									;; désempiler ecx
		pop ebx									;; désempiler ebx
	ret			

mzm endp
        
Align 16

IsDriveNW proc uses edi lDrive:DWORD
	
	mov 	edi,lDrive
	
	mov 	al,'\'
	cld
	or	 	ecx,-1
	repnz 	scasb
	jnz		@endl
	cmp 	ecx,0FFFFFFFEh
	jz 		@endl
	
	dec 	edi
	push 	edi
	xor 	al,al
	stosb
	add 	edi,ecx
	inc 	edi
	
	invoke 	GetDriveType,edi
	cmp 	eax,DRIVE_CDROM
	jne 	@F
		pop 	edi
		mov 	byte ptr [edi],'\'
		return_1
	@@:
	pop 	edi
	mov 	byte ptr [edi],'\'
	
@endl:
	xor 	eax,eax
	ret

IsDriveNW endp


Align 16

SetBmpColor proc hBitmap:DWORD

    LOCAL mDC       :DWORD
    LOCAL hBrush    :DWORD
    LOCAL hOldBmp   :DWORD
    LOCAL hReturn   :DWORD
    LOCAL hOldBrush :DWORD

      invoke CreateCompatibleDC,NULL
      mov mDC,eax

      invoke SelectObject,mDC,hBitmap
      mov hOldBmp,eax

      invoke GetSysColor,COLOR_BTNFACE
      invoke CreateSolidBrush,eax
      mov hBrush,eax

      invoke SelectObject,mDC,hBrush
      mov hOldBrush,eax

      invoke GetPixel,mDC,1,1
      invoke ExtFloodFill,mDC,1,1,eax,FLOODFILLSURFACE

      invoke SelectObject,mDC,hOldBrush
      invoke DeleteObject,hBrush

      invoke SelectObject,mDC,hBitmap
      mov hReturn,eax
      invoke DeleteDC,mDC

      mov eax,hReturn

    ret

SetBmpColor endp

align 16

GetAllDrives proc lpBuffer:DWORD, nSize:DWORD
	
	
	invoke RtlZeroMemory,lpBuffer,nSize
	invoke GetLogicalDriveStrings,nSize,lpBuffer
	
	ret

GetAllDrives endp

align 16

IsAnyRemovableExist proc uses edi
	LOCAL Rv,pDrives:DWORD
	
	; ------- seh installation ------- ;
	SehBegin	 __iare
	
	mov Rv,0
	invoke GlobalAlloc,GPTR,256
	.if eax
		mov pDrives,eax
		invoke GetAllDrives,pDrives,256
		.if eax
			mov edi,pDrives
			.if byte ptr [edi] != 0
				@lp:
				invoke GetDriveType,edi
				.if eax == DRIVE_REMOVABLE
					mov Rv,1
					jmp @freemem
				.endif
				NextArray @lp
			.endif
		.endif
		@freemem:
		invoke GlobalFree,pDrives
	.endif
	
	; ------- seh trapper ------- ;
	SehTrap 	__iare
		ErrorDump 	"IsAnyRemovableExist",offset IsAnyRemovableExist,offset szUtilsasm
	SehEnd 		__iare
	
	
	mov eax,Rv	
	
	ret

IsAnyRemovableExist endp

align 16

; ------- for killing a process in memory ------- ;
KillProcForcely proc lPID:DWORD
	LOCAL hProcess,hSnap:DWORD
	LOCAL retv:DWORD
	LOCAL lPID2:DWORD
	LOCAL te32:THREADENTRY32
	
	; ------- seh installation ------- ;
	SehBegin 	_kpf
	
	m2m 	lPID2,lPID

	mov 	retv,0
	
	invoke 	AppendLogConsole,reparg(" Try to kill uses level 1")
	
	; uses native api ZwOpenProcess
	invoke 	GetModuleHandle,ADDR szNtdll
	.if 	eax
		invoke 	GetProcAddress,eax,ADDR szZwOpenProcess
		.if 	eax
			mov 	_ZwOpenProcess,eax
			
			analloc 	18h
			test 	eax,eax
			jz 		NotUsesNative
			mov 	esi,eax
			
			lea 	eax,lPID2
			push 	eax 			; ===
			
			mov 	dword ptr [esi],18h
			push 	esi				; ===
			
			push 	PROCESS_TERMINATE	; ===
			
			lea 	eax,hProcess
			push 	eax				; ===
			
			call 	_ZwOpenProcess
			test 	eax,eax
			jz 		@F
			anfree 	esi
			jmp 	NotUsesNative
			@@:
			; now terminate
			invoke 	TerminateProcess,hProcess,0
			.if 	eax
				mov 	retv,1
				invoke 	AppendLogConsole,ADDR szSuccess
				jmp 	@endl
			.else
				invoke 	AppendLogConsole,ADDR szFailed
			.endif
			invoke 	CloseHandle,hProcess
			jmp 	@Force
		.else 	
			jmp 	NotUsesNative ; try
		.endif
	.else
		jmp 	NotUsesNative ; try
	.endif
	
NotUsesNative:

	invoke 	AppendLogConsole,reparg(" Escalate killer to level 2")
	invoke 	AppendLogConsole,reparg(" Try to kill uses level 2")

	invoke 	OpenProcess,PROCESS_ALL_ACCESS,0,lPID
	.if 	eax
		mov 	hProcess,eax
		
		invoke	TerminateProcess,hProcess,0
		.if 	eax
			mov 	retv,1
			invoke 	AppendLogConsole,ADDR szSuccess
		.else
			invoke 	AppendLogConsole,ADDR szFailed
		.endif 	
		
		invoke 	CloseHandle,hProcess
	.endif
	
; ------- failed? kill uses thread method ------- ;
	; forcely

	.if 	!retv
@Force:
		invoke 	AppendLogConsole,reparg(" Escalate killer to level 3")
		invoke 	AppendLogConsole,reparg(" Try to kill uses level 3")
		
		invoke 	MyZeroMemory,ADDR te32,sizeof THREADENTRY32
		invoke 	CreateToolhelp32Snapshot,TH32CS_SNAPTHREAD,lPID
		.if 	eax
			mov 	hSnap,eax
			mov 	[te32.dwSize],sizeof THREADENTRY32
			invoke 	Thread32First,hSnap,ADDR te32
			.if 	eax
				.while 	eax
					
					mov 	eax,[te32.th32OwnerProcessID]
					cmp 	eax,lPID
					jne 	@nx
						
						invoke 	OpenThread,THREAD_TERMINATE,0,[te32.th32ThreadID]
						.if 	eax
							push 	eax
							invoke 	TerminateThread,eax,'xxxx'
							.if 	eax
								mov 	retv,eax
								invoke 	AppendLogConsole,ADDR szSuccess
								jmp 	@closesnapend
							.else
								invoke 	AppendLogConsole,ADDR szFailed
							.endif
							call 	CloseHandle
						.endif
					@nx:
					invoke 	Thread32Next,hSnap,ADDR te32
				.endw
			.endif
@closesnapend:
			invoke 	CloseHandle,hSnap
		.endif
	.endif
	
@endl:

	; ------- seh trapper ------- ;
	SehTrap 	_kpf
		ErrorDump 	"KillProcForcely",offset KillProcForcely,offset szUtilsasm
	SehEnd 		_kpf


	mov 	eax,retv
	ret

KillProcForcely endp

align 16

KillObjectForcely proc uses ebx esi lpszFile:DWORD
	
	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	LOCAL 	retv,tmp:DWORD
	
	; ------- seh installation ------- ;
	SehBegin 	__kof
	
	mov 	CleanInArc,0
	mov 	retv,0
	
	mov 	ebx,AppendLogConsole
	
	scall 	ebx,reparg(" Try to clean this object :")
	scall 	ebx,lpszFile
	
	invoke 	IsObjectInsideArc?,lpszFile
	.if 	!eax
		
		invoke 	IsRootZip,lpszFile	; <-- don't kill zip file ;
		.if 	eax
			; check again is ok?
			mov 	retv,eax
			jmp 	@endl
		.endif
		
		;-------------------------------------- OUTSIDE ARC FILE ----------------------------------------;
		; ------- check for resident ------- ;
		invoke 	IsRunInMemory?,lpszFile
		.if 	eax
			scall 	ebx,reparg(" object running in memory")
			
			; ------- if resident kill it! ------- ;
			invoke 	KillProcForcely,eax
			.if 	!eax
				jmp 	@endl
			.endif
		.else
			scall 	ebx,reparg(" object not running in memory")
		.endif
		
		; ------- delete file ------- ;
		scall 	ebx,reparg(" Try to remove threat object")
		invoke 	FileExist,lpszFile
		.if 	!eax
			; ------- file not found ------- ;
			scall 	ebx,offset szFileDoesnEx
			mov 	retv,1
		.else
			invoke 	Sleep,10
			invoke 	DeleteFile,lpszFile
			.if 	eax
				
				invoke 	Sleep,200
				invoke 	FileExist,lpszFile
				.if 	eax
					jmp 	@failed
				.endif
				; -------------- ;
				
				mov 	retv,1
				scall 	ebx,offset szSuccess
				scall 	ebx,reparg(" Cleaning successfull")
			.else
			@failed:
				scall 	ebx,offset szFailed
				scall 	ebx,reparg(" Cleaning failed!")
			.endif
		.endif
	.else
		;-------------------------------------- INSIDE ARC FILE ----------------------------------------;
		
		mov 	CleanInArc,1
		
		scall 	ebx,reparg(" Try to neutralize object inside archive file...")
		inc 	SubArchive
		.if 	!ArcReady
			scall	ebx,reparg("archive type need module arc.dll to perform this action")
			jmp 	@endl
		.endif
		
		push 	offset szAnsavTempWorkDir	; <-- cleanup last temporary used ;
		call 	GenocideThisPath
		
		mov 	esi,lpszFile
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
	
	; ------- seh trapper ------- ;
	SehTrap 	__kof
		ErrorDump 	"KillObjectForcely",offset KillObjectForcely,offset szUtilsasm
	SehEnd 		__kof
	
	mov 	eax,retv
	ret

KillObjectForcely endp

align 16

SetShutdownTokenPrivilege proc uses ebx esi
	
	LOCAL 	luid:LUIDCUST
	LOCAL	ttoken:TOKEN_PRIVILEGES
	LOCAL 	pttoken:TOKEN_PRIVILEGES
	LOCAL 	hToken,hMyProcess:DWORD
	
	; ------- seh installation ------- ;
	SehBegin 	__sstp
	
	
	mov 	ebx,MyZeroMemory
	lea 	eax,luid
	scall 	ebx,eax,sizeof LUID
	lea 	eax,ttoken
	scall 	ebx,eax,sizeof TOKEN_PRIVILEGES
	lea 	eax,pttoken
	scall 	ebx,eax,sizeof TOKEN_PRIVILEGES
	
	call 	GetCurrentProcess
	mov 	hMyProcess,eax
	invoke 	OpenProcessToken,hMyProcess,TOKEN_ALL_ACCESS,ADDR hToken
	.if 	!eax
		call 	GetLastError
		mov 	ebx,eax
		analloc	256
		.if 	eax
			push 	eax
			mov 	esi,eax
			invoke 	wsprintf,eax,ADDR szAdjustPrivErrorF,ebx
			mWriteError	esi
			invoke 	MessageBox,hMainWnd,esi,ADDR szAppName,MB_ICONEXCLAMATION
			call 	GlobalFree
		.endif
		jmp 	@clean
		SehPop
		ret
	.endif
	szText 	szSeShutdownPrivilege,"SeShutdownPrivilege"
	
	invoke 	LookupPrivilegeValue,0,ADDR szSeShutdownPrivilege,ADDR luid
	.if 	!eax
		call 	GetLastError
		mov 	ebx,eax
		analloc 	256
		.if 	eax
			push 	eax
			mov 	esi,eax
			invoke 	wsprintf,eax,ADDR szAdjustPrivErrorF,ebx
			mWriteError esi
			invoke 	MessageBox,hMainWnd,esi,ADDR szAppName,MB_ICONEXCLAMATION
			call 	GlobalFree
		.endif
		jmp 	@clean
		SehPop
		ret
	.endif
	
	mov 	[ttoken.PrivilegeCount],1
	lea 	eax,luid
	mov 	eax,[luid.usedpart]
	mov 	[ttoken.Privileges.Luid.LowPart],eax
	mov 	eax,[luid.ignorehigh32bitpart]
	mov 	[ttoken.Privileges.Luid.HighPart],eax
	mov 	[ttoken.Privileges.Attributes],SE_PRIVILEGE_ENABLED
	

	; ------- adjust it ------- ;
	invoke 	AdjustTokenPrivileges,hToken,FALSE,ADDR ttoken,sizeof TOKEN_PRIVILEGES,ADDR pttoken,ADDR brw
	.if 	!eax
		call 	GetLastError
		mov 	ebx,eax
		analloc 	256
		.if 	eax
			push 	eax
			mov 	esi,eax
			invoke 	wsprintf,eax,ADDR szAdjustPrivErrorF,ebx
			mWriteError esi
			invoke 	MessageBox,hMainWnd,esi,ADDR szAppName,MB_ICONEXCLAMATION
			call 	GlobalFree
		.endif
		jmp 	@clean
		SehPop
		ret
	.endif
	
@clean:

	; ------- Seh trapper ------- ;
	SehTrap 	__sstp
		ErrorDump 	"SetShutdownTokenPrivilege",offset SetShutdownTokenPrivilege,offset szUtilsasm
	SehEnd 		__sstp


	invoke 	CloseHandle,hToken
	ret

SetShutdownTokenPrivilege endp

align 16

include 	inc\nrand.asm

align 16

Random	proc dwRange:DWORD

	invoke	nrandom,dwRange 	
	ret

Random endp

align 16

MakeRandomString	proc uses edi lpBuffer:DWORD,len:DWORD
	
	; ------- seh installation ------- ;
	SehBegin 	__mrs
	
	mov 	edi,lpBuffer
	mov 	eax,len
	inc 	eax
	invoke 	MyZeroMemory,edi,eax
	
	mov 	ecx,len
	@lp:
		push 	ecx
		invoke 	Random,8
		add 	eax,50
		stosb
		dec 	dword ptr [esp]
		.if 	!dword ptr [esp]
			add 	esp,4
			jmp 	@nx
		.endif
		invoke 	Random,56
		add 	eax,67
		stosb
		pop 	ecx
	loop 	@lp
@nx:

	; ------- seh trapper ------- ;
	SehTrap 	__mrs
		ErrorDump 	"MakeRandomString",offset MakeRandomString,offset szUtilsasm
	SehEnd 	__mrs
	
	ret

MakeRandomString endp

align 16

ChangeRandomString proc uses esi edi ebx ecx edx eax
	
	invoke 	MakeRandomString,ADDR szRandomString,10
	ret

ChangeRandomString endp

align 16

IsRunFromRemovable proc
	LOCAL 	lBuff[MAX_PATH]:BYTE
	
	lea 	edi,lBuff
	invoke 	GetModuleFileName,hInstance,edi,MAX_PATH
	.if 	byte ptr [edi]
		push 	edi
		mov 	al,'\'
		mov 	ecx,MAX_PATH
		repne 	scasb
		xor 	al,al
		stosb
		pop 	edi
		invoke 	GetDriveType,edi
		.if 	eax != DRIVE_FIXED
			return_1
		.endif
	.endif
	return_0
	ret

IsRunFromRemovable endp


.data
	szHashKey 	db 1,2,1,2,1,2,2,2,2,1,1
	HashKeySize equ $ - offset szHashKey
.code

align 16

anCrypto proc uses edi esi ebx lpBuffer:DWORD,lStr:DWORD
	
	lea 	ebx,szHashKey
	mov 	edi,lpBuffer
	mov 	esi,lStr
	
	strlen lStr
	
	mov 	ecx,eax
	@lp:
		mov 	al,byte ptr [esi]
		xor 	al,byte ptr [ebx]
		inc 	ebx
		inc 	esi
		mov 	byte ptr [edi],al
		inc 	edi
		mov 	eax,offset szHashKey
		add 	eax,HashKeySize
		cmp 	ebx,eax
		jb		@F
			lea 	ebx,szHashKey
		@@:
	loop 	@lp
	
	ret

anCrypto endp

align 16


BuildDirectoryFromPath proc lpPath:DWORD
	LOCAL	retv,len:DWORD
	LOCAL 	n:DWORD
	
	mov 	retv,0
	mov 	n,0
	
	mov 	esi,lpPath
	; get working dir
	
	strlen esi
	
	mov 	len,eax
	mov 	ecx,eax
	
	@lp:
		push 	ecx
		cmp 	byte ptr [esi+ecx],'\'
		jne 	@F
			inc 	n
			mov 	byte ptr [esi+ecx],0
			invoke 	SetLastError,0
			invoke 	GetFileAttributes,esi
			.if 	(eax != -1) && (ax & FILE_ATTRIBUTE_DIRECTORY) 
				call 	GetLastError
				.if 	(eax != ERROR_FILE_NOT_FOUND) && (eax != ERROR_PATH_NOT_FOUND) 
					pop 	ecx
					jmp 	@okay
				.endif
			.endif
		@@:
		pop 	ecx
	loop 	@lp
@okay:

	test 	ecx,ecx
	jz		@endl
	
	mov 	edi,esi
	@lp2:
		EndString MAX_PATH
		cmp 	byte ptr [edi+1],0
		je 		@outs
		cmp 	n,0
		je 		@outs
		mov 	byte ptr [edi],'\'
		invoke 	CreateDirectory,esi,0
		.if 	!eax
			jmp 	@endl
		.endif
		dec 	n
	jmp 	@lp2
@outs:
	mov 	retv,1

@endl:
	mov 	eax,retv
	ret

BuildDirectoryFromPath endp

align 16

GetCL proc ArgNum:DWORD, ItemBuffer:DWORD

  ; -------------------------------------------------
  ; arguments returned in "ItemBuffer"
  ;
  ; arg 0 = program name
  ; arg 1 = 1st arg
  ; arg 2 = 2nd arg etc....
  ; -------------------------------------------------
  ; Return values in eax
  ;
  ; 1 = successful operation
  ; 2 = no argument exists at specified arg number
  ; 3 = non matching quotation marks
  ; 4 = empty quotation marks
  ; -------------------------------------------------

    LOCAL lpCmdLine      :DWORD
    LOCAL cmdBuffer[192] :BYTE
    LOCAL tmpBuffer[192] :BYTE

    push esi
    push edi

    invoke GetCommandLine
    mov lpCmdLine, eax        ; address command line

  ; -------------------------------------------------
  ; count quotation marks to see if pairs are matched
  ; -------------------------------------------------
    xor ecx, ecx            ; zero ecx & use as counter
    mov esi, lpCmdLine
    
    @@:
      lodsb
      cmp al, 0
      je @F
      cmp al, 34            ; [ " ] character
      jne @B
      inc ecx               ; increment counter
      jmp @B
    @@:

    push ecx                ; save count

    shr ecx, 1              ; integer divide ecx by 2
    shl ecx, 1              ; multiply ecx by 2 to get dividend

    pop eax                 ; put count in eax
    cmp eax, ecx            ; check if they are the same
    je @F
      pop edi
      pop esi
      mov eax, 3            ; return 3 in eax = non matching quotation marks
      ret
    @@:

  ; ------------------------
  ; replace tabs with spaces
  ; ------------------------
    mov esi, lpCmdLine
    lea edi, cmdBuffer

    @@:
      lodsb
      cmp al, 0
      je rtOut
      cmp al, 9     ; tab
      jne rtIn
      mov al, 32
    rtIn:
      stosb
      jmp @B
    rtOut:
      stosb         ; write last byte

  ; -----------------------------------------------------------
  ; substitute spaces in quoted text with replacement character
  ; -----------------------------------------------------------
    lea eax, cmdBuffer
    mov esi, eax
    mov edi, eax

    subSt:
      lodsb
      cmp al, 0
      jne @F
      jmp subOut
    @@:
      cmp al, 34
      jne subNxt
      stosb
      jmp subSl     ; goto subloop
    subNxt:
      stosb
      jmp subSt

    subSl:
      lodsb
      cmp al, 32    ; space
      jne @F
        mov al, 254 ; substitute character
      @@:
      cmp al, 34
      jne @F
        stosb
        jmp subSt
      @@:
      stosb
      jmp subSl

    subOut:
      stosb         ; write last byte

  ; ----------------------------------------------------
  ; the following code determines the correct arg number
  ; and writes the arg into the destination buffer
  ; ----------------------------------------------------
    lea eax, cmdBuffer
    mov esi, eax
    lea edi, tmpBuffer

    mov ecx, 0          ; use ecx as counter

  ; ---------------------------
  ; strip leading spaces if any
  ; ---------------------------
    @@:
      lodsb
      cmp al, 32
      je @B

    l2St:
      cmp ecx, ArgNum     ; the number of the required cmdline arg
      je clSubLp2
      lodsb
      cmp al, 0
      je cl2Out
      cmp al, 32
      jne cl2Ovr           ; if not space

    @@:
      lodsb
      cmp al, 32          ; catch consecutive spaces
      je @B

      inc ecx             ; increment arg count
      cmp al, 0
      je cl2Out

    cl2Ovr:
      jmp l2St

    clSubLp2:
      stosb
    @@:
      lodsb
      cmp al, 32
      je cl2Out
      cmp al, 0
      je cl2Out
      stosb
      jmp @B

    cl2Out:
      mov al, 0
      stosb

  ; ------------------------------
  ; exit if arg number not reached
  ; ------------------------------
    .if ecx < ArgNum
      mov edi, ItemBuffer
      mov al, 0
      stosb
      mov eax, 2  ; return value of 2 means arg did not exist
      pop edi
      pop esi
      ret
    .endif

  ; -------------------------------------------------------------
  ; remove quotation marks and replace the substitution character
  ; -------------------------------------------------------------
    lea eax, tmpBuffer
    mov esi, eax
    mov edi, ItemBuffer

    rqStart:
      lodsb
      cmp al, 0
      je rqOut
      cmp al, 34    ; dont write [ " ] mark
      je rqStart
      cmp al, 254
      jne @F
      mov al, 32    ; substitute space
    @@:
      stosb
      jmp rqStart

  rqOut:
      stosb         ; write zero terminator

  ; ------------------
  ; handle empty quote
  ; ------------------
    mov esi, ItemBuffer
    lodsb
    cmp al, 0
    jne @F
    pop edi
    pop esi
    mov eax, 4  ; return value for empty quote
    ret
  @@:

    mov eax, 1  ; return value success

    pop edi
    pop esi

    ret

GetCL endp

align 16

GetInjectAbleProcess proc
	LOCAL 	hSnap:DWORD
	LOCAL 	lpe32:PROCESSENTRY32
	LOCAL 	retv:DWORD
	
	invoke 	MyZeroMemory,ADDR lpe32,sizeof PROCESSENTRY32
	mov 	retv,0
	
	mov 	[lpe32.dwSize],sizeof PROCESSENTRY32
	
	invoke 	CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS,0
	.if 	eax != -1
		mov 	hSnap,eax
		
		invoke 	Process32First,hSnap,ADDR lpe32
		.if 	eax
			.while 	eax
				.if 	[lpe32.th32ProcessID]>10
					lea 	edx,[lpe32.szExeFile]
					invoke 	lstrcmpi,edx,reparg("explorer.exe")
					jne 	@F
					invoke 	OpenProcess,PROCESS_ALL_ACCESS,0,[lpe32.th32ProcessID]
					.if 	eax
						push 	eax
						mov 	eax,[lpe32.th32ProcessID]
						mov 	retv,eax
						call 	CloseHandle
						jmp 	@endl
					.endif
				.endif
				@@:
				invoke 	Process32Next,hSnap,ADDR lpe32
			.endw
		.endif
@endl:
		invoke 	CloseHandle,hSnap
	.endif
	
	mov 	eax,retv
	ret

GetInjectAbleProcess endp

align 16

HexDump proc lpString:DWORD,lnString:DWORD,lpbuffer:DWORD

    LOCAL lcnt:DWORD

    push ebx
    push esi
    push edi

    jmp over_table
    align 16 
  hex_table:
    db "00","01","02","03","04","05","06","07","08","09","0A","0B","0C","0D","0E","0F"
    db "10","11","12","13","14","15","16","17","18","19","1A","1B","1C","1D","1E","1F"
    db "20","21","22","23","24","25","26","27","28","29","2A","2B","2C","2D","2E","2F"
    db "30","31","32","33","34","35","36","37","38","39","3A","3B","3C","3D","3E","3F"
    db "40","41","42","43","44","45","46","47","48","49","4A","4B","4C","4D","4E","4F"
    db "50","51","52","53","54","55","56","57","58","59","5A","5B","5C","5D","5E","5F"
    db "60","61","62","63","64","65","66","67","68","69","6A","6B","6C","6D","6E","6F"
    db "70","71","72","73","74","75","76","77","78","79","7A","7B","7C","7D","7E","7F"
    db "80","81","82","83","84","85","86","87","88","89","8A","8B","8C","8D","8E","8F"
    db "90","91","92","93","94","95","96","97","98","99","9A","9B","9C","9D","9E","9F"
    db "A0","A1","A2","A3","A4","A5","A6","A7","A8","A9","AA","AB","AC","AD","AE","AF"
    db "B0","B1","B2","B3","B4","B5","B6","B7","B8","B9","BA","BB","BC","BD","BE","BF"
    db "C0","C1","C2","C3","C4","C5","C6","C7","C8","C9","CA","CB","CC","CD","CE","CF"
    db "D0","D1","D2","D3","D4","D5","D6","D7","D8","D9","DA","DB","DC","DD","DE","DF"
    db "E0","E1","E2","E3","E4","E5","E6","E7","E8","E9","EA","EB","EC","ED","EE","EF"
    db "F0","F1","F2","F3","F4","F5","F6","F7","F8","F9","FA","FB","FC","FD","FE","FF"
  over_table:

    lea ebx, hex_table        ; get base address of table
    mov esi, lpString         ; address of source string
    mov edi, lpbuffer         ; address of output buffer
    mov eax, esi
    add eax, lnString
    mov ecx, eax              ; exit condition for byte read
    mov lcnt, 0

    xor eax, eax              ; prevent stall

  ; %%%%%%%%%%%%%%%%%%%%%%% loop code %%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  hxlp:
    mov al, [esi]             ; get BYTE
    inc esi
    inc lcnt
    mov dx, [ebx+eax*2]       ; put WORD from table into DX
    mov [edi], dx             ; write 2 byte string to buffer
    add edi, 2
    mov byte ptr [edi],'h'
    inc edi
    mov BYTE PTR [edi], ','    ; add comma
    inc edi
    cmp lcnt, 8               ; test for half to add "-"
    jne @F
    mov WORD PTR [edi], " -"
    add edi, 2
  @@:
    cmp lcnt, 16              ; break line at 16 characters
    jne @F
    dec edi                   ; overwrite last space
    mov WORD PTR [edi], 0A0Dh ; write CRLF to buffer
    add edi, 2
    mov lcnt, 0
  @@:
    cmp esi, ecx              ; test exit condition
    jl hxlp

  ; %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    inc edi
    mov BYTE PTR [edi], 0     ; append terminator

    pop edi
    pop esi
    pop ebx

    ret

HexDump endp

align 16

GenocideThisPath proc uses edi esi lpPath:DWORD
	
	LOCAL 	wfd:WIN32_FIND_DATA
	LOCAL 	hFind,l:DWORD
	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	
	; ------- seh installation ------- ;
	SehBegin 	__gtp
	
	
	lea 	esi,wfd
	invoke 	MyZeroMemory,esi,sizeof WIN32_FIND_DATA
	lea 	edi,lBuff
	invoke 	MyZeroMemory,edi,MAX_PATH
	
	invoke 	lstrcpy,edi,lpPath
	invoke 	TruePath,edi
	
	strlen edi
	
	mov 	l,eax
	mov 	byte ptr [edi+eax],'*'
	
	invoke 	FindFirstFile,edi,esi
	.if 	eax!=-1 && eax!=0
		mov 	hFind,eax
		.while 	eax
			
			lea 	eax,[wfd.cFileName]
			
			strlen eax
			
			.if 	eax>2 || byte ptr [wfd.cFileName]!='.'
				
				mov 	eax,l
				mov 	byte ptr [edi+eax],0
				lea 	eax,[wfd.cFileName]
				invoke 	lstrcat,edi,eax
				invoke 	GetFileAttributes,edi
				
				.if 	eax & FILE_ATTRIBUTE_DIRECTORY
					push edi
					invoke 	GenocideThisPath,edi
					invoke 	SetFileAttributes,edi,FILE_ATTRIBUTE_NORMAL
					invoke 	RemoveDirectory,edi
					pop edi
				.else
					invoke 	SetFileAttributes,edi,FILE_ATTRIBUTE_NORMAL
					invoke 	DeleteFile,edi
				.endif
				
			.endif
			
			invoke 	FindNextFile,hFind,esi
		.endw
		
		invoke 	FindClose,hFind
	.endif
	
	mov 	eax,l
	mov 	byte ptr [edi+eax],0
	invoke 	RemoveDirectory,edi

	; ------- seh trapper ------- ;
	SehTrap 	__gtp
		ErrorDump 	"GenocideThisPath",offset GenocideThisPath,"utils_ansav.asm"
	SehEnd 		__gtp

	
	ret

GenocideThisPath endp

align 16

FormatKB proc uses edi esi lpszSize:DWORD
	
	LOCAL lbuff[30]:BYTE
	
	lea 	esi,lbuff
	invoke	MyZeroMemory,esi,30
	
	mov 	edi,lpszSize
	strlen 	edi
	dec 	eax
	add 	esi,eax
	
	push 	eax
	
	xor 	edx,edx
	mov 	ecx,3
	div 	ecx
	add 	esi,eax
	
	pop 	ecx
	inc 	ecx
	dec 	edi
	xor 	eax,eax
	.while 	ecx
		mov 	dl,byte ptr [edi+ecx]
		
		.if 	eax==3
			mov 	byte ptr [esi],','
			sub 	esi,1
			xor 	eax,eax
		.endif
		mov 	byte ptr [esi],dl
		
		; <-- OPTIMIZED ;
		sub ecx,1
		sub esi,1
		add eax,1
		; <-- OPTIMIZED ;
	.endw	
	inc 	edi
	
	lea 	esi,lbuff
	invoke 	lstrcpyn,edi,esi,30
	mov 	eax,lpszSize
	ret

FormatKB endp

align 16

NextBootKillThisFile proc lpFile:DWORD
	
	invoke 	MoveFileEx,lpFile,0,MOVEFILE_DELAY_UNTIL_REBOOT
	
	ret

NextBootKillThisFile endp

align 16

ClipboardCopy proc hData:DWORD

	invoke 	GlobalAlloc,GMEM_SHARE,MAX_PATH
	test 	eax,eax
	jnz 	@F
		return_0
	@@:
	push 	eax
	push 	eax
	push 	eax
	push 	hData
	invoke 	GlobalLock,eax
	push 	eax
	call 	lstrcpy
	call 	GlobalUnlock
	invoke 	OpenClipboard,0
	call 	EmptyClipboard
	scall 	SetClipboardData,CF_TEXT
	call 	CloseClipboard
	
	ret

ClipboardCopy endp

align 16


TryKillAnsavgd proc

	LOCAL 	lpe32:PROCESSENTRY32
	mov 	[lpe32.dwSize],sizeof PROCESSENTRY32
	
	invoke 	CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS,0
	.if 	eax
		mov 	ebx,eax
		
		invoke 	Process32First,ebx,addr lpe32
		.if 	eax
			.while 	eax
				lea 	eax,lpe32.szExeFile
				invoke 	lstrcmpi,eax,reparg("ansavgd.exe")
				.if 	zero?
					invoke 	OpenProcess,PROCESS_ALL_ACCESS,0,[lpe32.th32ProcessID]
					.if 	eax
						mov 	esi,eax
						invoke 	TerminateProcess,esi,1
						invoke 	CloseHandle,esi
					.endif
				.endif
				invoke 	Process32Next,ebx,ADDR lpe32
			.endw
		.endif
		
		invoke 	CloseHandle,ebx
	.endif
	
	ret

TryKillAnsavgd endp

align 16

AntiDump proc uses esi
	
	LOCAL 	oldp:DWORD
	
    mov     esi, hInstance
    add     esi, 03ch
    add     si, word ptr [esi]
    sub     si, 03ch
    movzx   ecx, word ptr [esi+6]
    
    add     esi, 0f8h
    xor     edx, edx
    mov     eax, 028h
    dec     ecx
    mul     ecx
    lea     eax, [eax+esi]
    mov     ecx, eax
    mov     edx, [eax+0ch]
    add     edx, hInstance
    add     edx, [eax+010h]
    invoke 	VirtualProtect,edx,020h,PAGE_NOACCESS,offset brw	
	
	ret

AntiDump endp

align 16

IsAscii proc uses esi pstr:DWORD
	
	mov 	esi,pstr
	
	invoke 	MyStrLen,esi
	test 	eax,eax
	jnz 	@F
		ret
	@@:
	
	align 4
	xor 	ecx,ecx
	.while	ecx<eax
		cmp 	byte ptr [esi+ecx],32
		ja 	@F
			return_0
		@@:
		align 4
		cmp 	byte ptr [esi+ecx],126
		jb	@F
			return_0
		@@:
		add 	ecx,1
	.endw
	
	return_1
	ret

IsAscii endp

