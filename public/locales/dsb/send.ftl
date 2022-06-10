# Send is a brand name and should not be localized.
title = Send
importingFile = Importěrujo se...
encryptingFile = Koděrujo se...
decryptingFile = Dešifrěrujo se...
downloadCount =
    { $num ->
        [one] 1 ześěgnjenje
        [two] { $num } ześěgnjeni
        [few] { $num } ześěgnjenja
       *[other] { $num } ześěgnjenjow
    }
timespanHours =
    { $num ->
        [one] 1 góźina
        [two] { $num } góźinje
        [few] { $num } góźiny
       *[other] { $num } góźin
    }
copiedUrl = Kopěrowany!
unlockInputPlaceholder = Gronidło
unlockButtonLabel = Wótwóriś
downloadButtonLabel = Ześěgnuś
downloadFinish = Ześěgnjenje dokóńcone
fileSizeProgress = ({ $partialSize } z { $totalSize })
sendYourFilesLink = Send wopytaś
errorPageHeader = Něco njejo se raźiło!
fileTooBig = Toś ta dataja jo pśewjelika za nagraśe. Měła mjeńša ako { $size } byś.
linkExpiredAlt = Wótkaz spadnjony
notSupportedHeader = Waš wobglědowak se njepódpěra.
notSupportedLink = Cogodla se mój wobglědowak njepódpěra?
notSupportedOutdatedDetail = Bóžko toś ta wersija Firefox webtechnologiju njepódpěra, na kótarejž Send bazěrujo. Musyśo swój wobglědowak aktualizěrowaś.
updateFirefox = Firefox aktualizěrowaś
deletePopupCancel = Pśetergnuś
deleteButtonHover = Wulašowaś
footerLinkLegal = Pšawniske
footerLinkPrivacy = Priwatnosć
footerLinkCookies = Cookieje
passwordTryAgain = Wopacne gronidło. Wopytajśo hyšći raz.
javascriptRequired = Send JavaScript trjeba
whyJavascript = Cogodla Send JavaScript trjeba?
enableJavascript = Pšosym zmóžniśo JavaScript a wopytajśo hyšći raz.
# A short representation of a countdown timer containing the number of hours and minutes remaining as digits, example "13h 47m"
expiresHoursMinutes = { $hours } góź. { $minutes } min.
# A short representation of a countdown timer containing the number of minutes remaining as digits, example "56m"
expiresMinutes = { $minutes } min.
# A short status message shown when the user enters a long password
maxPasswordLength = Maksimalna dłujkosć gronidła: { $length }
# A short status message shown when there was an error setting the password
passwordSetError = Toś to gronidło njedajo se nastajiś

## Send version 2 strings

# Send, Send, Firefox, Mozilla are proper names and should not be localized
-send-brand = Send
-send-short-brand = Send
-firefox = Firefox
-mozilla = Mozilla
introTitle = Jadnore, priwatne datajowe źělenje
introDescription = { -send-brand } wam zmóžnja, dataje z koděrowanim kóńc do kóńca a wótkazom źěliś, kótaryž awtomatiski spadnjo. Tak móžośo źělone wopśimjeśe priwatne źaržaś a zawěsćiś, až waše daty online na pśecej njewóstanu.
notifyUploadEncryptDone = Waša dataja jo skoděrowana za słanje
# downloadCount is from the downloadCount string and timespan is a timespanMinutes string. ex. 'Expires after 2 downloads or 25 minutes'
archiveExpiryInfo = Spadnjo pó { $downloadCount } abo { $timespan }
timespanMinutes =
    { $num ->
        [one] { $num } minuta
        [two] { $num } minuśe
        [few] { $num } minuty
       *[other] { $num } minutow
    }
timespanDays =
    { $num ->
        [one] { $num } źeń
        [two] { $num } dnja
        [few] { $num } dny
       *[other] { $num } dnjow
    }
timespanWeeks =
    { $num ->
        [one] { $num } tyźeń
        [two] { $num } tyźenja
        [few] { $num } tyźenje
       *[other] { $num } tyźenjow
    }
fileCount =
    { $num ->
        [one] { $num } dataja
        [two] { $num } dataji
        [few] { $num } dataje
       *[other] { $num } datajow
    }
# byte abbreviation
bytes = B
# kibibyte abbreviation
kb = KB
# mebibyte abbreviation
mb = MB
# gibibyte abbreviation
gb = GB
# localized number and byte abbreviation. example "2.5MB"
fileSize = { $num }{ $units }
# $size is the size of the file, displayed using the fileSize message as format (e.g. "2.5MB")
totalSize = Cełkowna wjelikosć: { $size }
# the next line after the colon contains a file name
copyLinkDescription = Kopěrujśo wótkaz, aby swóju dataju źělił:
copyLinkButton = Wótkaz kopěrowaś
downloadTitle = Dataje ześěgnuś
downloadDescription = Toś ta dataja jo se pśez { -send-brand } z koděrowanim kóńc do kóńca a wótkazom źěliła, kótaryž awtomatiski spadnjo.
trySendDescription = Wopytajśo { -send-brand } za jadnore, wěste datajowe źělenje.
# count will always be > 10
tooManyFiles =
    { $count ->
        [one] Jano { $count } dataja dajo se naraz nagraś.
        [two] Jano { $count } dataji dajotej se naraz nagraś.
        [few] Jano { $count } dataje daju se naraz nagraś.
       *[other] Jano { $count } datajow dajo se naraz nagraś.
    }
# count will always be > 10
tooManyArchives =
    { $count ->
        [one] Jano { $count } archiw jo dowólony.
        [two] Jano { $count } archiwa stej dowólonej.
        [few] Jano { $count } archiwy su dowólone.
       *[other] Jano { $count } archiwow jo dowólone.
    }
expiredTitle = Toś ten wótkaz jo spadnjony.
notSupportedDescription = { -send-brand } z toś tym wobglědowakom njefunkcioněrujo. { -send-short-brand } nejlěpjej z nejnowšeju wersiju   funkcioněrujo, a funkcioněrujo z aktualneju wersiju nejwěcej wobglědowakow.
downloadFirefox =   ześěgnuś
legalTitle = Powěźeńka priwatnosći { -send-short-brand }
legalDateStamp = Wersija 1.0 wót 12. měrca 2019
# A short representation of a countdown timer containing the number of days, hours, and minutes remaining as digits, example "2d 11h 56m"
expiresDaysHoursMinutes = { $days }ź { $hours }g { $minutes }m
addFilesButton = Dataje za nagrawanje wubraś
trustWarningMessage = Wy měł dostawarjeju dowěriś, gaž sensibelne daty źěliśo.
uploadButton = Nagraś
# the first part of the string 'Drag and drop files or click to send up to 1GB'
dragAndDropFiles = Śěgniśo a wótpołožćo dataje
# the second part of the string 'Drag and drop files or click to send up to 1GB'
# $size is the size of the file, displayed using the fileSize message as format (e.g. "2.5MB")
orClickWithSize = abo klikniśo, aby do { $size } pósłał
addPassword = Z gronidłom šćitaś
emailPlaceholder = Zapódajśo swóju e-mailowu adresu
# $size is the size of the file, displayed using the fileSize message as format (e.g. "2.5MB")
signInSizeBump = Pśizjawśo se, aby do { $size } pósłał
signInOnlyButton = Pśizjawiś
accountBenefitTitle = Załožćo konto   abo pśizjawśo se
# $size is the size of the file, displayed using the fileSize message as format (e.g. "2.5MB")
accountBenefitLargeFiles = Dataje do { $size } źěliś
accountBenefitDownloadCount = Dataje z wěcej luźimi źěliś
accountBenefitTimeLimit =
    { $count ->
        [one] Wótkaze do { $count } dnja aktiwne źaržaś
        [two] Wótkaze do { $count } dnjowu aktiwne źaržaś
        [few] Wótkaze do { $count } dnjow aktiwne źaržaś
       *[other] Wótkaze do { $count } dnjow aktiwne źaržaś
    }
accountBenefitSync = Źělone dataje z někakego rěda zastojaś
accountBenefitMoz = Zgóńśo wěcej wó drugich słužbach { -mozilla }
signOut = Wótzjawiś
okButton = W pórěźe
downloadingTitle = Ześěgujo se
noStreamsWarning = Toś ten wobglědowak njamógał taku wjeliku dataju dešifrěrowaś.
noStreamsOptionCopy = Kopěrujśo wótkaz, aby jen w drugim wobglědowaku wócynił
noStreamsOptionFirefox = Wopytajśo naš nejlubšy wobglědowak
noStreamsOptionDownload = Z toś tym wobglědowakom pókšacowaś
downloadFirefoxPromo = { -send-short-brand } se wam pśez cele nowy   pśinjaso.
# the next line after the colon contains a file name
shareLinkDescription = Źělśo wótkaz k swójej dataji:
shareLinkButton = Wótkaz źěliś
# $name is the name of the file
shareMessage = Ześěgniśo „{ $name }“ z { -send-brand }: jadnore, wěste źělenje datajow
trailheadPromo = Jo móžnosć, wašu priwatnosć šćitaś. Pśiźćo k Firefox.
learnMore = Dalšne informacije.
downloadFlagged = Toś ten wótkaz jo se znjemóžnił pśestupjenja wužywańskich wuměnjenjow dla.
downloadConfirmTitle = Jadna wěc hyšći
downloadConfirmDescription = Wy měł wótpósłarjeju toś teje dataje dowěriś, dokulaž njamóžomy pśeglědaś, lěc to waš rěd kazy.
# This string has a special case for '1' and [other] (default). If necessary for
# your language, you can add {$count} to your translations and use the
# standard CLDR forms, or only use the form for [other] if both strings should
# be identical.
downloadTrustCheckbox =
    { $count ->
        [one] Dowěrim wósobje, kótaraž jo pósłała toś tu dataju
        [two] Dowěrim wósobje, kótaraž jo pósłała toś tej dataji
        [few] Dowěrim wósobje, kótaraž jo pósłała toś te dataje
       *[other] Dowěrim wósobje, kótaraž jo pósłała toś te dataje
    }
# This string has a special case for '1' and [other] (default). If necessary for
# your language, you can add {$count} to your translations and use the
# standard CLDR forms, or only use the form for [other] if both strings should
# be identical.
reportFile =
    { $count ->
        [one] Toś tu dataju ako suspektnu k wěsći daś
        [two] Toś tej dataji ako suspektnej k wěsći daś
        [few] Toś te dataje ako suspektne k wěsći daś
       *[other] Toś te dataje ako suspektne k wěsći daś
    }
reportDescription = Pomagajśo nam rozumić, co se stawa. Co pó wašom měnjenju njejo w pórědku z toś tymi datajami?
reportUnknownDescription = Źiśo pšosym k URL wótkaza, kótaryž cośo k wěsći daś a klikniśo na „{ reportFile }“.
reportButton = K wěsći daś
reportReasonMalware = Toś te dataje škódnu softwaru wopśimuju abo su źěl napada kšadnjenja datow.
reportReasonPii = Toś te dataje wósobinske informacije wó mnje, kótarež mógu mě identificěrowaś.
reportReasonAbuse = Toś te dataje njedowólone abo ranjece wopśimjeśe wopśimuju.
reportReasonCopyright = Aby pśestupjenje awtorskego pšawa abo pšawa wikowwych markow k wěsći dał, wužywajśo póstupowanje, kótarež se na <a>toś tom boku</a> wopisujo.
reportedTitle = Dataje k wěsći dane
reportedDescription = Wjeliki źěk. Smy dostali wašu rozpšawu wó toś tych datajach.
