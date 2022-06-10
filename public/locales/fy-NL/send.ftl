# Send is a brand name and should not be localized.
title = Send
importingFile = Ymportearje…
encryptingFile = Fersiferje…
decryptingFile = Untsiferje…
downloadCount =
    { $num ->
        [one] 1 download
       *[other] { $num } downloads
    }
timespanHours =
    { $num ->
        [one] 1 oer
       *[other] { $num } oer
    }
copiedUrl = Kopiearre!
unlockInputPlaceholder = Wachtwurd
unlockButtonLabel = Deblokkearje
downloadButtonLabel = Downloade
downloadFinish = Download foltôge
fileSizeProgress = ({ $partialSize } fan { $totalSize })
sendYourFilesLink = Send probearje
errorPageHeader = Der is wat misgien!
fileTooBig = It bestân is te grut om op te laden. It moat lytser wêze as { $size }.
linkExpiredAlt = Keppeling ferrûn
notSupportedHeader = Jo browser wurdt net stipe.
notSupportedLink = Wêrom wurdt myn browser net stipe?
notSupportedOutdatedDetail = Spitigernôch stipet dizze ferzje fan Firefox de webtechnology dy't Send mooflik makket net. Jo moatte jo browser fernije.
updateFirefox = Firefox fernije
deletePopupCancel = Annulearje
deleteButtonHover = Fuortsmite
footerLinkLegal = Juridysk
footerLinkPrivacy = Privacy
footerLinkCookies = Cookies
passwordTryAgain = Net krekt wachtwurd. Probearje it opnij.
javascriptRequired = Send fereasket JavaScript.
whyJavascript = Werom hat Send JavaScript nedich?
enableJavascript = Skeakelje JavaScript yn en probearje nochris.
# A short representation of a countdown timer containing the number of hours and minutes remaining as digits, example "13h 47m"
expiresHoursMinutes = { $hours }o { $minutes }m
# A short representation of a countdown timer containing the number of minutes remaining as digits, example "56m"
expiresMinutes = { $minutes }m
# A short status message shown when the user enters a long password
maxPasswordLength = Maksimale wachtwurdlingte: { $length }
# A short status message shown when there was an error setting the password
passwordSetError = Dit wachtwurd koe net ynsteld wurde

## Send version 2 strings

# Send, Send, Firefox, Mozilla are proper names and should not be localized
-send-brand = Send
-send-short-brand = Send
-firefox = Firefox
-mozilla = Mozilla
introTitle = Ienfâldich, privee bestannen diele
introDescription = Mei { -send-brand } kinne jo bestannen mei ein-ta-ein-fersifering en in automatysk ferrinnende keppeling diele. Sa kinne jo de dielde ynhâld privee hâlde, sadat jo gegevens net foar altyd online bliuwt.
notifyUploadEncryptDone = Jo bestân is fersifere en ree om te ferstjoeren
# downloadCount is from the downloadCount string and timespan is a timespanMinutes string. ex. 'Expires after 2 downloads or 25 minutes'
archiveExpiryInfo = Ferrint nei { $downloadCount } of { $timespan }
timespanMinutes =
    { $num ->
        [one] 1 minute
       *[other] { $num } minuten
    }
timespanDays =
    { $num ->
        [one] 1 dei
       *[other] { $num } dagen
    }
timespanWeeks =
    { $num ->
        [one] 1 wike
       *[other] { $num } wiken
    }
fileCount =
    { $num ->
        [one] 1 bestân
       *[other] { $num } bestannen
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
fileSize = { $num } { $units }
# $size is the size of the file, displayed using the fileSize message as format (e.g. "2.5MB")
totalSize = Totale grutte: { $size }
# the next line after the colon contains a file name
copyLinkDescription = Kopiearje de keppeling, om jo bestannen te dielen:
copyLinkButton = Keppeling kopierje
downloadTitle = Bestannen downloade
downloadDescription = Dit bestân is mei ein-ta-ein-fersifering en in keppeling dy't automatysk ferrint dield fia { -send-brand }.
trySendDescription = Probearje { -send-brand }, om ienfâldich en privee bestannen te dielen.
# count will always be > 10
tooManyFiles =
    { $count ->
        [one] Der kin maksimaal ien bestân opladen wurde.
       *[other] Der kinne maksimaal { $count } bestannen opladen wurde.
    }
# count will always be > 10
tooManyArchives =
    { $count ->
        [one] Der is mar ien argyf tastien.
       *[other] Der binne mar { $count } argiven tastien.
    }
expiredTitle = Dizze keppeling is ferrûn.
notSupportedDescription = { -send-brand } funksjonearret net mei dizze browser. { -send-short-brand } funksjonearret it bêste mei de nijste ferzje fan   en funksjonearret mei de aktuele ferzje fan de measte browsers.
downloadFirefox =   downloade
legalTitle = { -send-short-brand }-privacyferklearring
legalDateStamp = Ferzje 1.0, datearre 12 maart 2019
# A short representation of a countdown timer containing the number of days, hours, and minutes remaining as digits, example "2d 11h 56m"
expiresDaysHoursMinutes = { $days }d { $hours }o { $minutes }m
addFilesButton = Bestannen selektearje om op te laden
trustWarningMessage = Soargje derfoar dat jo jo ûntfanger fertrouwe wannear't jo gefoelige gegevens diele.
uploadButton = Oplade
# the first part of the string 'Drag and drop files or click to send up to 1GB'
dragAndDropFiles = Sleep en pleats bestannen
# the second part of the string 'Drag and drop files or click to send up to 1GB'
# $size is the size of the file, displayed using the fileSize message as format (e.g. "2.5MB")
orClickWithSize = of stjoer oant { $size } troch te klikken
addPassword = Mei wachtwurd beskermje
emailPlaceholder = Fier jo e-mailadres yn
# $size is the size of the file, displayed using the fileSize message as format (e.g. "2.5MB")
signInSizeBump = Meld jo oan, om bestannen oant { $size } te stjoeren
signInOnlyButton = Oanmelde
accountBenefitTitle = Meitsje in  -account of meld jo oan
# $size is the size of the file, displayed using the fileSize message as format (e.g. "2.5MB")
accountBenefitLargeFiles = Diel bestannen oant { $size }
accountBenefitDownloadCount = Diel bestannen mei mear minsken
accountBenefitTimeLimit =
    { $count ->
        [one] Keppeling oant ien dei lang aktyf hâlde
       *[other] Keppeling oant { $count } dagen lang aktyf hâlde
    }
accountBenefitSync = Behear dielde bestannen fan elk apparaat ôf
accountBenefitMoz = Lês mear oer oare { -mozilla }-tsjinsten
signOut = Ofmelde
okButton = OK
downloadingTitle = Downloade
noStreamsWarning = Dizze browser kin in sa'n grut bestân mooglik net fersiferje.
noStreamsOptionCopy = Kopiearje de koppeling om yn in oare browser te iepenjen
noStreamsOptionFirefox = Probearje ús favorite browser
noStreamsOptionDownload = Trochgean mei dizze browser
downloadFirefoxPromo = { -send-short-brand } wurdt jo oanbean troch it folslein fernijde  .
# the next line after the colon contains a file name
shareLinkDescription = Diel de keppeling nei jo bestân:
shareLinkButton = Keppeling diele
# $name is the name of the file
shareMessage = Download ‘{ $name }’ mei { -send-brand }: ienfâldich, feilich bestannen diele
trailheadPromo = Der is in manier om jo privacy te beskermjen. Doch mei mei Firefox.
learnMore = Mear ynfo.
downloadFlagged = Dizze keppeling is útskeakele fanwegen skeining fan de servicebetingsten.
downloadConfirmTitle = Noch ien ding
downloadConfirmDescription = Soargje derfoar dat jo de persoan fertrouwe dy't jo dit bestân stjoerd hat, omdat wy net ferifiearje kinne dat it jo apparaat net skansearje sil.
# This string has a special case for '1' and [other] (default). If necessary for
# your language, you can add {$count} to your translations and use the
# standard CLDR forms, or only use the form for [other] if both strings should
# be identical.
downloadTrustCheckbox =
    { $count ->
        [one] Ik fertrou de persoan dy't dit bestân stjoerd hat
       *[other] Ik fertrou de persoan dy't dizze bestannen stjoerd hat
    }
# This string has a special case for '1' and [other] (default). If necessary for
# your language, you can add {$count} to your translations and use the
# standard CLDR forms, or only use the form for [other] if both strings should
# be identical.
reportFile =
    { $count ->
        [one] Dit bestân as fertocht rapportearje
       *[other] Dizze bestannen as fertocht rapportearje
    }
reportDescription = Help ús te begripen wat der oan de hân is. Wat is der neffens jo mis mei dizze bestannen?
reportUnknownDescription = Gean nei de URL fan de keppeling dy't jo melde wolle en klik op ‘{ reportFile }’.
reportButton = Rapportearje
reportReasonMalware = Dizze bestannen befetsje malware of binne part fan in phishingoanfal.
reportReasonPii = Dizze bestannen befetsje persoanlik identifisearjende ynformaasje oer my.
reportReasonAbuse = Dizze bestannen befetsje yllegale of beledigjende ynhâld.
reportReasonCopyright = Brûk de proseduere op <a>dizze side</a> om ynbreuk op auteursrjochten of hannelsmerken te melden.
reportedTitle = Bestannen rapportearre
reportedDescription = Tank. Wy hawwe jo rapport oer dizze bestannen ûntfongen.
