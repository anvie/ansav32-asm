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

; ------- Included file for Version ------- ;
.const

	; ------- Version ------- ;
	VerMajor		dd 1
	VerMinor 		dd 9

IFDEF 	RELEASE
	VerRevision		dd 3
ELSE
	VerRevision		dd 3
ENDIF
	
.data
	; ------- Release Date ------- ;
	dwRDYear		dd 2008
	dwRDMonth 		dd 1
	dwRDDay			dd 9
.code
