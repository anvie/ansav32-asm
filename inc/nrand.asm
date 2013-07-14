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

; ллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
;
;                     Park Miller random number algorithm.
;
;                      Written by Jaymeson Trudgen (NaN)
;                   Optimized by Rickey Bowers Jr. (bitRAKE)
;
; ллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
	.data
		nrandom_seed dd 12345678
    .code

; ллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

align 4

nrandom PROC base:DWORD

    mov eax, nrandom_seed

  ; ****************************************
    test eax, 80000000h
    jz  @F
    add eax, 7fffffffh
  @@:   
  ; **************************************** 

    xor edx, edx
    mov ecx, 127773
    div ecx
    mov ecx, eax
    mov eax, 16807
    mul edx
    mov edx, ecx
    mov ecx, eax
    mov eax, 2836
    mul edx
    sub ecx, eax
    xor edx, edx
    mov eax, ecx
    mov nrandom_seed, ecx
    div base

    mov eax, edx
    ret

nrandom ENDP

; ллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

nseed proc TheSeed:DWORD

    mov eax, TheSeed
    mov nrandom_seed, eax

    ret

nseed endp
