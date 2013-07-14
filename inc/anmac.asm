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

; ------- Macro Library  ------- ;


szText MACRO Name, Text:VARARG
	LOCAL lbl
	jmp lbl
		Name db Text,0
	lbl:
endm


cText MACRO Name, Text:VARARG
	LOCAL Name
	.data
		Name 	db Text,0
	.code	
	
endm

leatext	MACRO Text:VARARG
	LOCAL 	nustr
	.data
		nustr db Text,0
	.code
	lea 	eax,nustr
	EXITM 	<eax>
endm


	m2m 	MACRO M1,M2
		push 	M2
		pop 	M1
	endm
	

    NextArray MACRO NAM
        xor eax, eax
        or  ecx, -1
        repnz scasb                                 ;| MACRO FOR FUTURE USE
        cmp byte ptr [edi], 0
        jne NAM
    ENDM

    EndString MACRO Jml
        mov     ecx, Jml
        xor     al,al
        repne   scasb
        dec     edi
    ENDM

    MovZero MACRO Jml
    	LOCAL 	lbl
        push    edi
        mov     ecx, Jml
        sub 	eax,eax
        mov 	edx,ecx
        and 	edx,3
        shr 	ecx,2
        cld
        rep     stosd
        or 		ecx,edx
        jz 		lbl
        
        rep 	stosb
        
        lbl:
        pop     edi
    ENDM

    SetHiddenAttr MACRO lpFile
        invoke  SetFileAttributes, lpFile, FILE_ATTRIBUTE_HIDDEN OR FILE_ATTRIBUTE_SYSTEM
    ENDM
    
    SetNormalAttr MACRO lpFile
        invoke  SetFileAttributes, lpFile, FILE_ATTRIBUTE_NORMAL
    ENDM

    Kill MACRO lpFile
        invoke  DeleteFile, lpFile
    ENDM

    MsgBox MACRO msgHwnd, szMessg
        push 0
        push offset szAppName
        push szMessg
        push msgHwnd
        call MessageBox
    ENDM

    SehBegin MACRO Handler
     	  pushad
        assume fs:nothing
     	  mov ecx, offset Handler	
     	  push ecx
     	  push dword ptr fs:[0]
     	  mov dword ptr fs:[0], esp
    ENDM	
    
    SehTrap MACRO Handler	
     	  jmp NoException&Handler
     	  align 4
    Handler:
    
    	  mov esp, [esp + 8]
     	  pop dword ptr fs:[0]	
     	  add esp, 4	
     	  popad
    ENDM	
    
    SehEnd MACRO Handler	
     	  jmp ExceptionHandled&Handler
     	  ; ------- need for speed ------- ;
     	  align 4
     	  nop
     	  ; ------- need for speed ------- ;
    NoException&Handler:	 		
     	  pop dword ptr fs:[0]
     	  db 3eh
     	  add esp, 32+4
    ExceptionHandled&Handler:	 		
    ENDM
    
    SehPop MACRO 
    	pop 	dword ptr fs:[0]
    	db 3eh
    	add 	esp,32+4
    endm

    mstrcpy MACRO 
        LOCAL jbak

        push esi
        push edi
        push eax

    jbak:
        mov al,byte ptr [esi]
        mov byte ptr [edi],al
        inc edi
        inc esi
        cmp al,0
        jne jbak

        mov byte ptr [edi],0

		pop eax
        pop edi
        pop esi
    ENDM


    reparg MACRO arg
      LOCAL nustr
        quot SUBSTR <arg>,1,1
      IFIDN quot,<">            ;; if 1st char = "
        .data
          nustr db arg,0        ;; write arg to .DATA section
        .code
        EXITM <offset nustr>      ;; append name to ADDR operator
      ELSE
        EXITM <arg>             ;; else return arg
      ENDIF
    ENDM
    
      mkdir MACRO dirname
        invoke CreateDirectory,reparg(dirname),NULL
      ENDM
      MKDIR equ <mkdir>
        
	return_1	MACRO
		xor 	eax,eax
		inc 	eax
		ret
	endm
	
	return 		MACRO	dv 
		mov 	eax,dv
		ret
	endm
	
	return_0 MACRO
		xor 	eax,eax
		ret	
	endm

	analloc MACRO nSize
		invoke GlobalAlloc,GPTR,nSize
	endm
	
	anfree MACRO hm
		invoke GlobalFree,hm
	endm

	valloc MACRO nSize
		invoke VirtualAlloc,0,nSize,MEM_COMMIT,PAGE_EXECUTE_READWRITE
	endm
	
	vfree MACRO hdl
		invoke VirtualFree,hdl,0,MEM_RELEASE
	endm
	
	ViewError MACRO	hWin,arg 			; --------------------[ -= Macro for debug =- ]
		LOCAL 	nustr
		quot 	SUBSTR <arg>,1,1
		push 	MB_ICONEXCLAMATION
		push 	offset szAppName
		IFIDN	quot,<">
			.data
				nustr 	db "ERROR: ",arg,0
			.code
			push 	offset nustr
		ELSE
			push 	arg
		ENDIF
		push 	hWin
		call 	MessageBox
		;invoke 	MessageBox,hWin,ADDR nustr,ADDR szAppName,MB_ICONEXCLAMATION
	endm
	
	
	RevEax	MACRO 
		
		neg 	eax
		setz	al
		movzx 	eax,al
		
	endm
	
scall MACRO name:REQ,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12, \
                     p13,p14,p15,p16,p17,p18,p19,p20,p21,p22

    ;; ---------------------------------------
    ;; loop through arguments backwards, push
    ;; NON blank ones and call the function.
    ;; ---------------------------------------

    FOR arg,<p22,p21,p20,p19,p18,p17,p16,p15,p14,p13,\
             p12,p11,p10,p9,p8,p7,p6,p5,p4,p3,p2,p1>
      IFNB <arg>    ;; If not blank
        push arg    ;; push parameter
      ENDIF
    ENDM

    call name       ;; call the procedure

ENDM


mov2	MACRO r1,r2
	mov 	eax,r2
	mov 	r1,eax
endm

Align8 MACRO
	nop
	nop
	nop
	nop
	Align 4
endm

msign MACRO reg
IFDEF DEBUG
	mov reg,reg
ENDIF
endm

strlen MACRO strl

; changed/added 01:00 05-sept-2007 by anvie ------o
	
;	LOCAL lbl
	
;	mov ecx,strl
;	mov edx,ecx
;	lbl:
;		mov al,byte ptr [edx]
;		inc edx
;		test al,al
;		jne lbl
;	dec edx
;	sub edx,ecx
;	mov eax,edx

	push 	strl
	call 	MyStrLen
endm

; ------- optimized 5x cycle faster than lstrlen default system ------- ;
align 16

MyStrLen proc item:DWORD

    mov     ecx, [esp+2*4]
    test    ecx, 3
    jz      @max8

@bucle:
    mov     al, [ecx]
    add     ecx, 1
    test    al, al
    jz      @lb1

    test    ecx, 3
    jnz     @bucle
align 4
@max8:
    mov     eax, [ecx]
    mov     edx, 7EFEFEFFh
    add     edx, eax
    xor     eax, 0FFFFFFFFh
    xor     eax, edx
    add     ecx, 4
    test    eax, 81010100h
    jz      @max8

    mov     eax, [ecx-4]
    test    al, al
    jz      @lb4

    test    ah, ah
    jz      @lb3

    test    eax, 0FF0000h
    jz      @lb2

    test    eax, 0FF000000h
    jnz     @max8

@lb1:
    lea     eax, [ecx-1]
    mov     ecx, [esp+2*4]
    sub     eax, ecx
    ret     1*4

@lb2:
    lea     eax, [ecx-2]
    mov     ecx, [esp+2*4]
    sub     eax, ecx
    ret     1*4

@lb3:
    lea     eax, [ecx-3]
    mov     ecx, [esp+2*4]
    sub     eax, ecx
    ret     1*4

@lb4:
    lea     eax, [ecx-4]
    mov     ecx, [esp+2*4]
    sub     eax, ecx
    ret     1*4

	ret		1*4
MyStrLen endp

align 16

; changed/added 01:00 05-sept-2007 by anvie ------x

