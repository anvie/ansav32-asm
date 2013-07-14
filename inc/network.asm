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

include 	wininet.inc
includelib 	wininet.lib

;-------------------------------------- network.asm ----------------------------------------;


IsConnectedToInternet? proc
	
	push 	0
	push 	0
	call 	InternetGetConnectedState
	ret

IsConnectedToInternet? endp

align 16

