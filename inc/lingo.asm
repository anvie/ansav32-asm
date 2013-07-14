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


;-------------------------------------- lingo.asm ----------------------------------------;
; added by anvie 4:52 5-Sept-2007
; 32 bit len algorithm by lingo

Align 16                                ; Align 16 before the proc

InStringL proc lpSource:DWORD, lpPattern:DWORD
         db    3Eh                     ; ds: prefix
         mov   eax, [esp+8]            ; ecx->lpPattern
         sub   esp, 2*4                ; room to save registers and lenght of substring
         db    3Eh                     ;
         mov   edx, [esp+2*4]          ; edx-> return address
         db    3Eh                     ;
         mov   ecx, [eax]              ; get dword from substring
         db    3Eh                     ;
         mov   [esp+2*4], ebx          ; save register ebx
         movzx ebx, cl                 ; ebx->the 1st byte of substring
         db    3Eh                     ;
         mov   [esp+4*4], edx          ; save return address
         imul  ebx, 1010101h           ; ebx=77 77 77 77h  ; 77h -> ASCII code of "w"
         db    3Eh                     ;   (if the 1st byte of substring is "w")
         mov   [esp], esi              ;          
         lea   esi, [eax-1]            ; esi-> lpPattern-1
         mov   [esp+1*4], edi          ; save register edi
         mov   edx, 80808080h          ;
         mov   edi, [esp+3*4]          ; edi-> lpSource
         mov   [esp+3*4], ebp          ; save register ebp
         mov   ebp, 0FEFEFEFFh         ; ebp=0FEFEFEFFh
LoopS1:                                 ; my strlen with substring
         add   eax, 4                  ; ecx->lpPattern
         add   ecx, ebp                ; ebp=0FEFEFEFFh
         test  edx, ecx                ;
         mov   ecx, [eax]              ; get dword from substring
         je    LoopS1                  ; 2 clocks per 4 bytes
         cmp   byte ptr [eax-4], 0     ;
         je    S1_minus4               ;
         cmp   byte ptr [eax-4+1], 0   ;
         je    S1_minus3               ;
         cmp   byte ptr [eax-4+2], 0   ;
         je    S1_minus2               ;
         cmp   byte ptr [eax-4+3], 0   ;
         jne   LoopS1                  ; if not zeroes loop again
         sub   eax, 2                  ;
S1:                                     ;
         mov   ebp, [edi]              ;
         sub   eax, esi                ; end my strlen with substring
         mov   ecx, -4                 ;
         push  eax                     ; save len of substring in variable
BytesScan:                              ;
         db    3Eh                     ; ds: prefix
         lea   edx, [ebp-1010101h]     ; searching the 1st byte of substring or/and zero
         xor   ebp, ebx                ; ebx=77 77 77 77h  ; 77h -> ASCII code of "w"
         db    3Eh                     ;   (if the 1st byte of substring is "w")
         add   edi, 4                  ;              
         sub   ebp, 1010101h           ;
         or    edx, ebp                ; testing the 1st byte of substring and 0
         db    3Eh                     ;   simultaneously in the larger string
         mov   ebp, [edi]              ;  
         and   edx, 80808080h          ;
         je    BytesScan               ; 4 clocks per 4 bytes
SrchNextByte:                           ;
         cmp   [edi+ecx], bl           ; bl = 77h -> ASCII code of "w
         je    StartCmp                ;   (if the 1st byte of substring is "w")
         cmp   byte ptr [edi+ecx], 0   ; is it the end of the larger string?
         je    ExitP                   ; exit
ToNext:                                 ;
         inc   ecx                     ; ecx-> -4 to 0
         jne   SrchNextByte            ;
         mov   ebp, [edi]              ; restoring ebp for ByteScan
         sub   ecx, 4                  ; ecx = -4
         jc    BytesScan               ; loop again
align 16                                ;
S1_minus4:                              ;
         db    3Eh                     ; ds: prefix
         sub   eax, 5                  ;
         jno   S1                      ;
S1_minus3:                              ;
         sub   eax, 4                  ;
         jno   S1                      ;
S1_minus2:                              ;
         sub   eax, 3                  ;
         jno   S1                      ;
StartCmp:                               ; comparing next bytes from substring
         mov   edx,  [esp]             ; edx-> len of substring
         lea   ebp, [edi+ecx]          ; ebp=edi+ecx -> as a base register
         movzx eax, byte ptr [esi+edx] ; comparing rest bytes
         dec   edx                     ;
         je    ExitP                   ; exit
CmpNext:                                ;
         cmp   [ebp+edx], al           ; ebp->lp to current 1st byte in the larger string
         jne   ToNext                  ;
         movzx eax, byte ptr [esi+edx] ; get next byte
         dec   edx                     ;
         jne   CmpNext                 ; 2 clocks per byte
ExitP:                                  ;
         mov   esi, [esp+1*4]          ; restoring register esi
         cmp   edx, 1                  ; if edx= 0 mask = 0FFFFFFFFh else mask=0
         sbb   eax, eax                ; eax->mask 0 or 0FFFFFFFFh
         mov   edi, [esp+2*4]          ; restoring register edi
         and   eax, ebp                ; eax->lp 1st occurrence in large string or zero
         mov   ebx, [esp+3*4]          ; restoring register ebx
         mov   ebp, [esp+4*4]          ; restoring register ebp
         add   esp, 5*4                ; restoring register esp
         ret                           ; faster return then ret  2*4
InStringL endp
