# Send is a brand name and should not be localized.
title = Send
importingFile = Ojegueruhína…
encryptingFile = Mo’ãmby…
decryptingFile = Ñemo’ã’o…
downloadCount =
    { $num ->
        [one] 1 mboguejy
       *[other] { $num } mboguejy
    }
timespanHours =
    { $num ->
        [one] 1 aravo
       *[other] { $num } aravo
    }
copiedUrl = Monguatiapyre!
unlockInputPlaceholder = Ñe’ẽñemi
unlockButtonLabel = Mbojera
downloadButtonLabel = Mboguejy
downloadFinish = Oguejypáma
fileSizeProgress = ({ $partialSize } rehe { $totalSize })
sendYourFilesLink = Eipuru Send
errorPageHeader = ¡Oiko jejavy!
fileTooBig = Marandurenda tuichaiterei ehupi hag̃ua. Michĩveva’erã { $size } gui.
linkExpiredAlt = Juajuha ndoikóiva
notSupportedHeader = Ne kundaha ndorekói pytyvõ.
notSupportedLink = ¿Mba’ére che kundahára ndorekói ñepytyvõ?
notSupportedOutdatedDetail = Ko Firefox rembiapo ndaipu’akái ñanduti rembipurupyahu oikotevẽva Send. Embohekopyahúke ne kundahára.
updateFirefox = Firefox mbohekopyahu
deletePopupCancel = Heja
deleteButtonHover = Mboguete
footerLinkLegal = Añetegua
footerLinkPrivacy = Ñemigua
footerLinkCookies = Kookie
passwordTryAgain = Ñe’ẽñemi ndoikóiva. Eha’ãjey.
javascriptRequired = Send oikotevẽ JavaScript
whyJavascript = ¿Mba’ére Send oikotevẽ JavaScript?
enableJavascript = Ikatúpa embojuruja JavaScript ha eha’ãjey uperire.
# A short representation of a countdown timer containing the number of hours and minutes remaining as digits, example "13h 47m"
expiresHoursMinutes = { $hours } h { $minutes } m
# A short representation of a countdown timer containing the number of minutes remaining as digits, example "56m"
expiresMinutes = { $minutes } m
# A short status message shown when the user enters a long password
maxPasswordLength = Ñe’ẽñemi pukukue: { $length }
# A short status message shown when there was an error setting the password
passwordSetError = Ndaikatúi oikóvo ko ñe’ẽñemi

## Send version 2 strings

# Send, Send, Firefox, Mozilla are proper names and should not be localized
-send-brand = Send
-send-short-brand = Send
-firefox = Firefox
-mozilla = Mozilla
introTitle = Marandurenda ñemoambue hasy’ỹ ha ñemiguáva
introDescription = { -send-brand } omoherakuãkuaa marandurenda papapýpe ñepyrũ guive opa peve ha juajuha opareíva ijehegui. Ikatu oreko ñemihápe emoherakuãva ha ehecháta mba’éicha ne mba’ekuéra noĩri ñandutípe opa ára.
notifyUploadEncryptDone = Ne marandurenda oñemo’ã ha ikatúma emondo
# downloadCount is from the downloadCount string and timespan is a timespanMinutes string. ex. 'Expires after 2 downloads or 25 minutes'
archiveExpiryInfo = Opáta { $downloadCount } rire térã { $timespan }
timespanMinutes =
    { $num ->
        [one] 1 aravo’i
       *[other] { $num } aravo’i
    }
timespanDays =
    { $num ->
        [one] 1 ára
       *[other] { $num } ára
    }
timespanWeeks =
    { $num ->
        [one] 1 arapokõindy
       *[other] { $num } arapokõindy
    }
fileCount =
    { $num ->
        [one] 1 marandurenda
       *[other] { $num } marandurenda
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
totalSize = Tuichakue: { $size }
# the next line after the colon contains a file name
copyLinkDescription = Emonguatia juajuha ha emoherakuã ne marandurenda:
copyLinkButton = Emonguatia juajuha
downloadTitle = Emboguejy marandurenda
downloadDescription = Ko marandurenda omoherakuã { -send-brand } rupive papapýpe ñepyrũ guive opa peve ha juajuha opáva ijehegui reheve.
trySendDescription = Eipuru { -send-brand } emoherakuã hag̃ua marandurenda tasy’ỹ ha tekorosãme.
# count will always be > 10
tooManyFiles =
    { $count ->
        [one] Ikatu ehupi 1 marandurenda oñondive
       *[other] Ikatu ehupi { $count } marandurenda oñondive
    }
# count will always be > 10
tooManyArchives =
    { $count ->
        [one] Oñemoneĩ 1 marandurenda añoite
       *[other] Oñemoneĩ { $count } marandurenda añoite
    }
expiredTitle = Ko juajuha ndoikovéima.
notSupportedDescription = { -send-brand } ndoikomo’ãi ko kundahára ndive. { -send-short-brand } oikoporãvéta   rembiapokue ipyahuvéva ndive, ha oikóta opavavete kundahára ndive.
downloadFirefox = Emboguejy  
legalTitle = { -send-short-brand } Marandu ñemigua
legalDateStamp = Mba’epyahu 1.0, 12 jasyapy 2019 peguare
# A short representation of a countdown timer containing the number of days, hours, and minutes remaining as digits, example "2d 11h 56m"
expiresDaysHoursMinutes = { $days }d { $hours }h { $minutes }m
addFilesButton = Eiporavo marandurenda ehupi hag̃ua
trustWarningMessage = Ejerovia añetépa emondotaháre emoherakuãvo mba’ekuaarã kañyguáva.
uploadButton = Hupi
# the first part of the string 'Drag and drop files or click to send up to 1GB'
dragAndDropFiles = Embosyryry ha epoi marandurenda
# the second part of the string 'Drag and drop files or click to send up to 1GB'
# $size is the size of the file, displayed using the fileSize message as format (e.g. "2.5MB")
orClickWithSize = térã eikutu emondo hag̃ua { $size } peve
addPassword = Ñe’ẽñemíme mo’ãmbyre
emailPlaceholder = Emoinge ne ñanduti veve
# $size is the size of the file, displayed using the fileSize message as format (e.g. "2.5MB")
signInSizeBump = Eñepyrũ tembiapo emondo hag̃ua { $size } peve
signInOnlyButton = Eñepyrũ tembiapo
accountBenefitTitle = Emoheñói   mba’ete térã eñepyrũ tembiapo
# $size is the size of the file, displayed using the fileSize message as format (e.g. "2.5MB")
accountBenefitLargeFiles = Emoherakuã marandurenda { $size } peve
accountBenefitDownloadCount = Emoherakuã marandurenda hetave tapicha ndive
accountBenefitTimeLimit =
    { $count ->
        [one] Eguereko juajuha hendyhápe 1 ára
       *[other] Eguereko juajuha hendyhápe { $count } ára
    }
accountBenefitSync = Eñangareko marandurenda moherakuãmbyrére oimeraẽ mba’e’oka guive.
accountBenefitMoz = Eikuaa ambue { -mozilla } mba’epytyvõrã
signOut = Emboty tembiapo
okButton = OK
downloadingTitle = Oñemboguejyhína
noStreamsWarning = Ikatu ko kundahára ndoikuaái marandurenda tuichaitereíva.
noStreamsOptionCopy = Embokuatia juajuha embojuruja hag̃ua ambue kundahárape.
noStreamsOptionFirefox = Eipuru ore kundahára rohayhuvéva
noStreamsOptionDownload = Eku’ejey ko kundahára ndive
downloadFirefoxPromo = Ipyahúva   ome’ẽse ndéve { -send-short-brand }.
# the next line after the colon contains a file name
shareLinkDescription = Emoherakuã juajuha ne mba’e’oka ndive:
shareLinkButton = Emoherakuã juajuha
# $name is the name of the file
shareMessage = Emboguejy “{ $name }” { -send-brand } ndive: emoherakuã marandurenda tasy’ỹ ha tekorosãme
trailheadPromo = Mba’éichapa emo’ãta ne ñemigua. Eipuru Firefox.
learnMore = Kuaave.
downloadFlagged = Ko juajuha ojepe’áma ombyai rupi mba’epytyvõrã ñemboguata.
downloadConfirmTitle = Peteĩ mba’eve
downloadConfirmDescription = Ejerovia añetépa pe tapicha oguerukáva ndéve ko marandurenda ndaikatúire rohechajey ne mba’e’oka.
# This string has a special case for '1' and [other] (default). If necessary for
# your language, you can add {$count} to your translations and use the
# standard CLDR forms, or only use the form for [other] if both strings should
# be identical.
downloadTrustCheckbox =
    { $count ->
        [one] Ajerovia tapicháre orukáva ko marandurenda
       *[other] Ajerovia umi tapicha orukáva ko’ã marandurenda
    }
# This string has a special case for '1' and [other] (default). If necessary for
# your language, you can add {$count} to your translations and use the
# standard CLDR forms, or only use the form for [other] if both strings should
# be identical.
reportFile =
    { $count ->
        [one] Ehechauka ko marandurenda imarãkuaávarõ
       *[other] Ehechauka ko’ã marandurenda imarãkuaávarõ
    }
reportDescription = Orepytyvõ roikumbývo mba’épa oiko. ¿Mba’épa ere oĩvaiha ko’ã marandurenda ndive?
reportUnknownDescription = Eikundaha pe url juajuha ekoroiseha ndive ha eikutu “{ reportFile }”.
reportButton = Ekorói
reportReasonMalware = Ko’ã marandurenda oreko tembiaporape imarãva térã oñembyaikuaáva.
reportReasonPii = Ko’ã marandurenda oreko marandu nemba’etéva che kuaaukakuaáva.
reportReasonAbuse = Ko’ã marandurenda oreko tetepy ivai térã imbaretéva.
reportReasonCopyright = Ekoróitarõ derécho ñembyaíre térã marca registrada, ehecha jehaipyre <a>ko kuatiaroguépe</a>.
reportedTitle = Marandurenda jekoroihague
reportedDescription = Aguyje. Og̃uahẽ nde jekorói ko’ã marandurenda rehegua.
