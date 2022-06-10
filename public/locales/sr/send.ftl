# Send is a brand name and should not be localized.
title = Send
importingFile = Увозим…
encryptingFile = Шифрујем…
decryptingFile = Дешифрујем…
downloadCount =
    { $num ->
        [one] { $num } преузимања
        [few] { $num } преузимања
       *[other] { $num } преузимања
    }
timespanHours =
    { $num ->
        [one] { $num } сата
        [few] { $num } сата
       *[other] { $num } сати
    }
copiedUrl = Ископирано!
unlockInputPlaceholder = Лозинка
unlockButtonLabel = Откључај
downloadButtonLabel = Преузми
downloadFinish = Преузимање је завршено.
fileSizeProgress = ({ $partialSize } од { $totalSize })
sendYourFilesLink = Испробајте Send
errorPageHeader = Нешто је пошло наопако!
fileTooBig = Та датотека је превелика за отпремање. Треба да буде мања од { $size }.
linkExpiredAlt = Веза је истекла
notSupportedHeader = Ваш прегледач није подржан.
notSupportedLink = Зашто мој прегледач није подржан?
notSupportedOutdatedDetail = Нажалост, ово издање Firefox-a не подржава веб технологију која омогућава Send. Мораћете да ажурирате ваш прегледач.
updateFirefox = Ажурирај Firefox
deletePopupCancel = Откажи
deleteButtonHover = Обриши
footerLinkLegal = Правни подаци
footerLinkPrivacy = Приватност
footerLinkCookies = Колачићи
passwordTryAgain = Нетачна лозинка. Пробајте поново.
javascriptRequired = За Send је потребан JavaScript
whyJavascript = Зашто је потребан JavaScript за Send?
enableJavascript = Омогућите JavaScript и пробајте поново.
# A short representation of a countdown timer containing the number of hours and minutes remaining as digits, example "13h 47m"
expiresHoursMinutes = { $hours }ч { $minutes }м
# A short representation of a countdown timer containing the number of minutes remaining as digits, example "56m"
expiresMinutes = { $minutes }м
# A short status message shown when the user enters a long password
maxPasswordLength = Највећа дужина лозинке: { $length }
# A short status message shown when there was an error setting the password
passwordSetError = Не можемо поставити ову лозинку

## Send version 2 strings

# Send, Send, Firefox, Mozilla are proper names and should not be localized
-send-brand = Send
-send-short-brand = Send
-firefox = Firefox
-mozilla = Mozilla
introTitle = Једноставно и приватно дељење датотека
introDescription = { -send-brand } вам дозвољава да делите датотеке које су шифроване с краја на крај преко везе која самостално истиче. Тако да можете приватно делити ваше ствари које неће остати на вебу заувек.
notifyUploadEncryptDone = Ваша датотека је шифрована и спремна за слање
# downloadCount is from the downloadCount string and timespan is a timespanMinutes string. ex. 'Expires after 2 downloads or 25 minutes'
archiveExpiryInfo = Истиче након { $downloadCount } или { $timespan }
timespanMinutes =
    { $num ->
        [one] { $num } минут
        [few] { $num } минута
       *[other] { $num } минута
    }
timespanDays =
    { $num ->
        [one] { $num } дан
        [few] { $num } дана
       *[other] { $num } дана
    }
timespanWeeks =
    { $num ->
        [one] { $num } недеља
        [few] { $num } недеље
       *[other] { $num } недеља
    }
fileCount =
    { $num ->
        [one] { $num } датотека
        [few] { $num } датотеке
       *[other] { $num } датотека
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
totalSize = Укупна величина: { $size }
# the next line after the colon contains a file name
copyLinkDescription = Копирајте везу да бисте поделили вашу датотеку:
copyLinkButton = Копирај везу
downloadTitle = Преузми датотеке
downloadDescription = Ова датотека је подељена преко услуге { -send-brand } која омогућава шифровање с краја на крај преко везе која самостално истиче.
trySendDescription = Пробајте { -send-brand } за једноставно и безбедно дељење датотека.
# count will always be > 10
tooManyFiles =
    { $count ->
        [one] Можете отпремити само { $count } датотеку истовремено.
        [few] Можете отпремити само { $count } датотеке истовремено.
       *[other] Можете отпремити само { $count } датотека истовремено.
    }
# count will always be > 10
tooManyArchives =
    { $count ->
        [one] Дозвољена је само { $count } архива.
        [few] Дозвољене су само { $count } архиве.
       *[other] Дозвољено је само { $count } архива.
    }
expiredTitle = Ова веза је истекла.
notSupportedDescription = { -send-brand } неће радити у овом прегледачу. { -send-short-brand } најбоље ради са последњим издањем прегледача   и радиће са тренутним издањима већине других прегледача.
downloadFirefox = Преузми  
legalTitle = Политика приватности услуге { -send-short-brand }
legalDateStamp = Издање 1.0, датум објављивања 12. март 2019. године
# A short representation of a countdown timer containing the number of days, hours, and minutes remaining as digits, example "2d 11h 56m"
expiresDaysHoursMinutes = { $days }д { $hours }ч { $minutes }м
addFilesButton = Изаберите датотеке за отпремање
trustWarningMessage = Будите сигурни да верујете примаоцу пре дељења осетљивих података.
uploadButton = Отпреми
# the first part of the string 'Drag and drop files or click to send up to 1GB'
dragAndDropFiles = Превуците и пустите датотеке
# the second part of the string 'Drag and drop files or click to send up to 1GB'
# $size is the size of the file, displayed using the fileSize message as format (e.g. "2.5MB")
orClickWithSize = или кликните за слање садржаја великог до { $size }
addPassword = Заштитите лозинком
emailPlaceholder = Унесите вашу е-адресу
# $size is the size of the file, displayed using the fileSize message as format (e.g. "2.5MB")
signInSizeBump = Пријавите се да пошаљете садржај до { $size }
signInOnlyButton = Пријавите се
accountBenefitTitle = Направите   налог или се пријавите
# $size is the size of the file, displayed using the fileSize message as format (e.g. "2.5MB")
accountBenefitLargeFiles = Поделите датотеке велике до { $size }
accountBenefitDownloadCount = Поделите датотеке са више особа
accountBenefitTimeLimit =
    { $count ->
        [one] Остави везе активним највише { $count } дан
        [few] Остави везе активним највише { $count } дана
       *[other] Остави везе активним највише { $count } дана
    }
accountBenefitSync = Управљајте подељеним датотекама са било ког уређаја
accountBenefitMoz = Сазнајте више о другим { -mozilla }-иним услугама
signOut = Одјава
okButton = У реду
downloadingTitle = Преузимам
noStreamsWarning = Овај прегледач можда неће моћи да дешифрује оволико велику датотеку.
noStreamsOptionCopy = Копирај везу за отварање у другом прегледачу
noStreamsOptionFirefox = Пробајте наш омиљени прегледач
noStreamsOptionDownload = Наставите у овом прегледачу
downloadFirefoxPromo = { -send-short-brand } вам је омогућен захваљући потпуно новом програму  .
# the next line after the colon contains a file name
shareLinkDescription = Поделите везу до датотеке:
shareLinkButton = Поделите везу
# $name is the name of the file
shareMessage = Преузмите „{ $name }“ помоћу програма { -send-brand }:  једноставно и безбедно дељење датотека
trailheadPromo = Постоји начин да заштитите вашу приватност. Придружите се Firefox-у.
learnMore = Сазнајте више.
downloadFlagged = Ова веза је онемогућена због кршења услова услуге.
downloadConfirmTitle = Још једна ствар
downloadConfirmDescription = Будите сигурни да верујете особи која вам је послала ову датотеку, јер не можемо обећати да неће оштетити ваш уређа.
# This string has a special case for '1' and [other] (default). If necessary for
# your language, you can add {$count} to your translations and use the
# standard CLDR forms, or only use the form for [other] if both strings should
# be identical.
downloadTrustCheckbox =
    { $count ->
        [one] Верујем особи која је послала ову датотеку
        [few] Верујем особи која је послала ове датотеке
       *[other] Верујем особама које су послале ове датотеке
    }
# This string has a special case for '1' and [other] (default). If necessary for
# your language, you can add {$count} to your translations and use the
# standard CLDR forms, or only use the form for [other] if both strings should
# be identical.
reportFile =
    { $count ->
        [one] Пријави ову датотеку као сумњиву
        [few] Пријави ове датотеке као сумњиве
       *[other] Пријави ове датотеке као сумњиве
    }
reportDescription = Помозите нам да схватимо шта се дешава. Шта мислите да није у реду са овим датотекама?
reportUnknownDescription = Идите на адресу везе коју желите да пријавите и изаберите “{ reportFile }”.
reportButton = Пријави
reportReasonMalware = Ове датотеке садрже злонамеран софтвер или су део напада за крађу идентитета.
reportReasonPii = Ове датотеке садрже моје личне податке.
reportReasonAbuse = Ове датотеке садрже илегални или насилни садржај.
reportReasonCopyright = Да бисте пријавили кршење ауторских права или заштитног знака, следите кораке на <a>овој страници</a>.
reportedTitle = Датотеке су пријављене
reportedDescription = Хвала вам. Примили смо вашу пријаву ових датотека.
