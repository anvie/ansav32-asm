;------------------------------------------------------------------------------;
;
;   ANSAV An's Antivirus
;   Copyright (C) 2007-2008 Muqorrobien Ma'rufi a.k.a 4NV|e
;   
;   Muqorrobien Ma'rufi a.k.a 4NV|e
;   anvie_2194 @ yahoo.com
;   http://www.ansav.com
;   PP. Miftahul Huda Blok C Siwatu Wonosobo 56352 Jawa Tengah Indonesia
;   
;
;------------------------------------------------------------------------------;

; #########################################################################

  ; ---------------------------------------------------------------
  ;      This procedure was originally written by Tim Roberts 
  ;
  ; Part of this code has been optimised by Alexander Yackubtchik
  ; ---------------------------------------------------------------

.code

atodw proc String:DWORD

  ; ----------------------------------------
  ; Convert decimal string into dword value
  ; return value in eax
  ; ----------------------------------------

    push esi
    push edi

    xor eax, eax
    mov esi, [String]
    xor ecx, ecx
    xor edx, edx
    mov al, [esi]
    inc esi
    cmp al, 2D
    jne proceed
    mov al, byte ptr [esi]
    not edx
    inc esi
    jmp proceed

  @@: 
    sub al, 30h
    lea ecx, dword ptr [ecx+4*ecx]
    lea ecx, dword ptr [eax+2*ecx]
    mov al, byte ptr [esi]
    inc esi

  proceed:
    or al, al
    jne @B
    lea eax, dword ptr [edx+ecx]
    xor eax, edx

    pop edi
    pop esi

    ret

atodw endp
