# Send is a brand name and should not be localized.
title = Send
importingFile = S'està important…
encryptingFile = S'està xifrant…
decryptingFile = S'està desxifrant…
downloadCount =
    { $num ->
        [one] 1 baixada
       *[other] { $num } baixades
    }
timespanHours =
    { $num ->
        [one] 1 hora
       *[other] { $num } hores
    }
copiedUrl = Copiat!
unlockInputPlaceholder = Contrasenya
unlockButtonLabel = Desbloca
downloadButtonLabel = Baixa
downloadFinish = Ha acabat la baixada
fileSizeProgress = ({ $partialSize } de { $totalSize })
sendYourFilesLink = Proveu el Send
errorPageHeader = Hi ha hagut un problema
fileTooBig = Aquest fitxer és massa gros per pujar-lo. Ha de tenir menys de { $size }.
linkExpiredAlt = L'enllaç ha caducat
notSupportedHeader = El vostre navegador no és compatible.
notSupportedLink = Per què el meu navegador no és compatible?
notSupportedOutdatedDetail = Aquesta versió del Firefox no admet la tecnologia web amb què funciona el Send. Haureu d'actualitzar el navegador.
updateFirefox = Actualitza el Firefox
deletePopupCancel = Cancel·la
deleteButtonHover = Suprimeix
footerLinkLegal = Avís legal
footerLinkPrivacy = Privadesa
footerLinkCookies = Galetes
passwordTryAgain = La contrasenya és incorrecta. Torneu-ho a provar.
javascriptRequired = El Send necessita JavaScript
whyJavascript = Per què el Send necessita JavaScript?
enableJavascript = Activeu el JavaScript i torneu-ho a provar.
# A short representation of a countdown timer containing the number of hours and minutes remaining as digits, example "13h 47m"
expiresHoursMinutes = { $hours } h { $minutes } min
# A short representation of a countdown timer containing the number of minutes remaining as digits, example "56m"
expiresMinutes = { $minutes } min
# A short status message shown when the user enters a long password
maxPasswordLength = Longitud màxima de la contrasenya: { $length }
# A short status message shown when there was an error setting the password
passwordSetError = No s'ha pogut definir la contrasenya

## Send version 2 strings

# Send, Send, Firefox, Mozilla are proper names and should not be localized
-send-brand = Send
-send-short-brand = Send
-firefox = Firefox
-mozilla = Mozilla
introTitle = Compartició de fitxers senzilla i privada
introDescription = El { -send-brand } permet compartir fitxers amb xifratge d'extrem a extrem mitjançant un enllaç que caduca automàticament. Per tant, us assegureu que tot allò que compartiu és privat i que no es mantindrà a Internet per sempre.
notifyUploadEncryptDone = El fitxer s'ha xifrat i està llest per enviar-se
# downloadCount is from the downloadCount string and timespan is a timespanMinutes string. ex. 'Expires after 2 downloads or 25 minutes'
archiveExpiryInfo = Caduca després de { $downloadCount } o { $timespan }
timespanMinutes =
    { $num ->
        [one] 1 minut
       *[other] { $num } minuts
    }
timespanDays =
    { $num ->
        [one] 1 dia
       *[other] { $num } dies
    }
timespanWeeks =
    { $num ->
        [one] 1 setmana
       *[other] { $num } setmanes
    }
fileCount =
    { $num ->
        [one] 1 fitxer
       *[other] { $num } fitxers
    }
# byte abbreviation
bytes = B
# kibibyte abbreviation
kb = kB
# mebibyte abbreviation
mb = MB
# gibibyte abbreviation
gb = GB
# localized number and byte abbreviation. example "2.5MB"
fileSize = { $num }{ $units }
# $size is the size of the file, displayed using the fileSize message as format (e.g. "2.5MB")
totalSize = Mida total: { $size }
# the next line after the colon contains a file name
copyLinkDescription = Copieu l'enllaç per compartir el fitxer:
copyLinkButton = Copia l'enllaç
downloadTitle = Baixa els fitxers
downloadDescription = Aquest fitxer s'ha compartit mitjançant el { -send-brand } amb xifratge d'extrem a extrem i un enllaç que caduca automàticament.
trySendDescription = Proveu el { -send-brand } per compartir fitxers de forma senzilla i privada.
# count will always be > 10
tooManyFiles =
    { $count ->
        [one] Només es pot pujar 1 fitxer alhora.
       *[other] Només es poden pujar { $count } fitxers alhora.
    }
# count will always be > 10
tooManyArchives =
    { $count ->
        [one] Només es permet 1 fitxer.
       *[other] Només es permeten { $count } fitxers.
    }
expiredTitle = Aquest enllaç ha caducat.
notSupportedDescription = El { -send-brand } no funcionarà amb aquest navegador. El { -send-short-brand } funciona millor amb l'última versió del   i funcionarà amb la versió més recent de la majoria de navegadors.
downloadFirefox = Baixa el  
legalTitle = Avís de privadesa del { -send-short-brand }
legalDateStamp = Versió 1.0, amb data del 12 de març de 2019
# A short representation of a countdown timer containing the number of days, hours, and minutes remaining as digits, example "2d 11h 56m"
expiresDaysHoursMinutes = { $days } d { $hours } h { $minutes } min
addFilesButton = Seleccioneu els fitxers que voleu pujar
trustWarningMessage = Assegureu-vos que confieu en el destinatari quan compartiu dades confidencials.
uploadButton = Puja
# the first part of the string 'Drag and drop files or click to send up to 1GB'
dragAndDropFiles = Arrossegueu i deixeu anar els fitxers
# the second part of the string 'Drag and drop files or click to send up to 1GB'
# $size is the size of the file, displayed using the fileSize message as format (e.g. "2.5MB")
orClickWithSize = o feu clic aquí per enviar fins a { $size }
addPassword = Protegeix amb contrasenya
emailPlaceholder = Introduïu la vostra adreça electrònica
# $size is the size of the file, displayed using the fileSize message as format (e.g. "2.5MB")
signInSizeBump = Inicieu la sessió per enviar fins a { $size }
signInOnlyButton = Inicia la sessió
accountBenefitTitle = Creeu un compte del   o inicieu la sessió
# $size is the size of the file, displayed using the fileSize message as format (e.g. "2.5MB")
accountBenefitLargeFiles = Compartiu fitxers fins a { $size }
accountBenefitDownloadCount = Compartiu fitxers amb més persones
accountBenefitTimeLimit =
    { $count ->
        [one] Manteniu els enllaços actius fins a 1 dia
       *[other] Manteniu els enllaços actius fins a { $count } dies
    }
accountBenefitSync = Gestioneu els fitxers compartits des de qualsevol dispositiu
accountBenefitMoz = Descobriu els altres serveis de { -mozilla }
signOut = Tanca la sessió
okButton = D'acord
downloadingTitle = S'està baixant
noStreamsWarning = Pot ser que aquest navegador no pugui desxifrar un fitxer tan gran.
noStreamsOptionCopy = Copieu l'enllaç per obrir-lo en un altre navegador
noStreamsOptionFirefox = Proveu el nostre navegador preferit
noStreamsOptionDownload = Segueix amb aquest navegador
downloadFirefoxPromo = El nou   us ofereix el { -send-short-brand }
# the next line after the colon contains a file name
shareLinkDescription = Compartiu l'enllaç al vostre fitxer:
shareLinkButton = Comparteix l'enllaç
# $name is the name of the file
shareMessage = Baixeu «{ $name }» amb el { -send-brand }: compartició de fitxers senzilla i segura
trailheadPromo = Hi ha una manera de protegir la vostra privadesa. Uniu-vos al Firefox.
learnMore = Més informació.
downloadFlagged = Aquest enllaç s'ha desactivat per infringir les condicions del servei.
downloadConfirmTitle = Una cosa més
downloadConfirmDescription = Assegureu-vos que confieu en la persona que us ha enviat aquest fitxer, perquè nosaltres no podem verificar que no malmeti el vostre dispositiu.
# This string has a special case for '1' and [other] (default). If necessary for
# your language, you can add {$count} to your translations and use the
# standard CLDR forms, or only use the form for [other] if both strings should
# be identical.
downloadTrustCheckbox =
    { $count ->
        [one] Confio en la persona que ha enviat aquest fitxer
       *[other] Confio en la persona que ha enviat aquests fitxers
    }
# This string has a special case for '1' and [other] (default). If necessary for
# your language, you can add {$count} to your translations and use the
# standard CLDR forms, or only use the form for [other] if both strings should
# be identical.
reportFile =
    { $count ->
        [one] Informa que aquest fitxer és sospitós
       *[other] Informa que aquests fitxers són sospitos
    }
reportDescription = Ajudeu-nos a entendre què passa. Quin problema creieu que tenen aquests fitxers?
reportUnknownDescription = Aneu a l'URL de l'enllaç sobre el qual voleu informar i feu clic a «{ reportFile }».
reportButton = Informa
reportReasonMalware = Aquests fitxers contenen programari maliciós o formen part d'un atac de pesca electrònica.
reportReasonPii = Aquests fitxers contenen informació d'identificació personal meva.
reportReasonAbuse = Aquests fitxers inclouen contingut il·legal o abusiu.
reportReasonCopyright = Per informar sobre una infracció de drets d’autor o de marca comercial, utilitzeu el procés descrit en <a>aquesta pàgina</a>.
reportedTitle = S'ha informat d'aquests fitxers
reportedDescription = Gràcies. Hem rebut el vostre informe sobre aquests fitxers.
