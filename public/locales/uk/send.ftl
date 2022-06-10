# Send is a brand name and should not be localized.
title = Send
importingFile = Імпортуємо...
encryptingFile = Шифруємо...
decryptingFile = Розшифровуємо...
downloadCount =
    { $num ->
        [one] 1 завантаження
        [few] { $num } завантаження
       *[other] { $num } завантажень
    }
timespanHours =
    { $num ->
        [one] 1 година
        [few] { $num } години
       *[other] { $num } годин
    }
copiedUrl = Скопійовано!
unlockInputPlaceholder = Пароль
unlockButtonLabel = Розблокувати
downloadButtonLabel = Завантажити
downloadFinish = Завантаження завершено
fileSizeProgress = ({ $partialSize } з { $totalSize })
sendYourFilesLink = Спробуйте Send
errorPageHeader = Щось пішло не так!
fileTooBig = Цей файл завеликий для вивантаження. Він має бути меншим за { $size }.
linkExpiredAlt = Час дії посилання минув
notSupportedHeader = Ваш браузер не підтримується.
notSupportedLink = Чому мій браузер не підтримується?
notSupportedOutdatedDetail = На жаль, ця версія Firefox не підтримує веб-технологію, завдяки якій працює Send. Вам потрібно оновити свій браузер.
updateFirefox = Оновити Firefox
deletePopupCancel = Скасувати
deleteButtonHover = Видалити
footerLinkLegal = Права
footerLinkPrivacy = Приватність
footerLinkCookies = Куки
passwordTryAgain = Невірний пароль. Спробуйте знову.
javascriptRequired = Send потребує JavaScript
whyJavascript = Чому для Send потрібен JavaScript?
enableJavascript = Будь ласка, увімкніть JavaScript та спробуйте знову.
# A short representation of a countdown timer containing the number of hours and minutes remaining as digits, example "13h 47m"
expiresHoursMinutes = { $hours } год. { $minutes } хв.
# A short representation of a countdown timer containing the number of minutes remaining as digits, example "56m"
expiresMinutes = { $minutes } хв.
# A short status message shown when the user enters a long password
maxPasswordLength = Найбільша довжина паролю: { $length }
# A short status message shown when there was an error setting the password
passwordSetError = Неможливо встановити цей пароль

## Send version 2 strings

# Send, Send, Firefox, Mozilla are proper names and should not be localized
-send-brand = Send
-send-short-brand = Send
-firefox = Firefox
-mozilla = Mozilla
introTitle = Простий, приватний обмін файлами
introDescription = { -send-brand } дозволяє обмінюватися файлами з використанням наскрізного шифрування та посиланнями з обмеженим терміном дії. Отже, ви можете бути певними, що ваші дані зберігаються приватно і не залишаться в мережі назавжди.
notifyUploadEncryptDone = Ваш файл зашифрований і готовий до надсилання
# downloadCount is from the downloadCount string and timespan is a timespanMinutes string. ex. 'Expires after 2 downloads or 25 minutes'
archiveExpiryInfo = Термін зберігання завершується після { $downloadCount } або { $timespan }
timespanMinutes =
    { $num ->
        [one] 1 хвилина
        [few] { $num } хвилини
       *[other] { $num } хвилин
    }
timespanDays =
    { $num ->
        [one] 1 день
        [few] { $num } дні
       *[other] { $num } днів
    }
timespanWeeks =
    { $num ->
        [one] 1 тиждень
        [few] { $num } тижні
       *[other] { $num } тижнів
    }
fileCount =
    { $num ->
        [one] 1 файл
        [few] { $num } файли
       *[other] { $num } файлів
    }
# byte abbreviation
bytes = Б
# kibibyte abbreviation
kb = КБ
# mebibyte abbreviation
mb = МБ
# gibibyte abbreviation
gb = ГБ
# localized number and byte abbreviation. example "2.5MB"
fileSize = { $num }{ $units }
# $size is the size of the file, displayed using the fileSize message as format (e.g. "2.5MB")
totalSize = Загальний розмір: { $size }
# the next line after the colon contains a file name
copyLinkDescription = Скопіюйте посилання для спільного доступу:
copyLinkButton = Копіювати посилання
downloadTitle = Завантажити файли
downloadDescription = Цей файл було надіслано через { -send-brand } з використанням наскрізного шифрування і посиланням, що має обмежений термін дії.
trySendDescription = Спробуйте { -send-brand } для простого, захищеного обміну файлами.
# count will always be > 10
tooManyFiles =
    { $count ->
        [one] Лише 1 файл можна вивантажити за один раз.
        [few] Лише { $count } файли можна вивантажити за один раз.
       *[other] Лише { $count } файлів можна вивантажити за один раз.
    }
# count will always be > 10
tooManyArchives =
    { $count ->
        [one] Дозволяється лише 1 архів.
        [few] Дозволяється лише { $count } архіви.
       *[other] Дозволяється лише { $count } архівів.
    }
expiredTitle = Термін дії цього посилання завершився.
notSupportedDescription = { -send-brand } не працюватиме з цим браузером. { -send-short-brand } найкраще працює з найновішою версією  , а також з більшістю інших браузерів.
downloadFirefox = Завантажити  
legalTitle = Повідомлення про приватність { -send-short-brand }
legalDateStamp = Версія 1.0 від 12 березня 2019 року
# A short representation of a countdown timer containing the number of days, hours, and minutes remaining as digits, example "2d 11h 56m"
expiresDaysHoursMinutes = { $days }д { $hours }г { $minutes }хв
addFilesButton = Оберіть файли для вивантаження
trustWarningMessage = Переконайтеся, що довіряєте одержувачу коли ділитеся вразливими даними.
uploadButton = Вивантажити
# the first part of the string 'Drag and drop files or click to send up to 1GB'
dragAndDropFiles = Перетягуйте файли
# the second part of the string 'Drag and drop files or click to send up to 1GB'
# $size is the size of the file, displayed using the fileSize message as format (e.g. "2.5MB")
orClickWithSize = або натисніть, щоб надіслати до { $size }
addPassword = Захист паролем
emailPlaceholder = Введіть свою електронну пошту
# $size is the size of the file, displayed using the fileSize message as format (e.g. "2.5MB")
signInSizeBump = Увійдіть, щоб надсилати файли розміром до { $size }
signInOnlyButton = Увійти
accountBenefitTitle = Створіть обліковий запис   або увійдіть
# $size is the size of the file, displayed using the fileSize message as format (e.g. "2.5MB")
accountBenefitLargeFiles = Обмінюйтесь файлами розміром до { $size }
accountBenefitDownloadCount = Обмінюйтесь файлами з більшою кількістю людей
accountBenefitTimeLimit =
    { $count ->
        [one] Термін дії посилання 1 день
        [few] Термін дії посилання { $count } дні
       *[many] Термін дії посилання { $count } днів
    }
accountBenefitSync = Керуйте спільними файлами з буль-якого пристрою
accountBenefitMoz = Дізнайтеся про інші сервіси { -mozilla }
signOut = Вийти
okButton = Гаразд
downloadingTitle = Завантаження
noStreamsWarning = Цьому браузеру може не вдатися розшифрувати такий великий файл.
noStreamsOptionCopy = Скопіюйте посилання, щоб відкрити його в іншому браузері
noStreamsOptionFirefox = Спробуйте наш улюблений браузер
noStreamsOptionDownload = Продовжити в цьому браузері
downloadFirefoxPromo = { -send-short-brand } доступний для вас в цілком новому  .
# the next line after the colon contains a file name
shareLinkDescription = Надішліть посилання на свій файл:
shareLinkButton = Поділитись посиланням
# $name is the name of the file
shareMessage = Завантажте “{ $name }” з { -send-brand }: простий та безпечний обмін файлами
trailheadPromo = Існує спосіб захистити вашу приватність. Приєднуйтесь до Firefox.
learnMore = Докладніше.
downloadFlagged = Це посилання вимкнено через порушення умов надання послуг.
downloadConfirmTitle = Ще порада
downloadConfirmDescription = Переконайтеся, що довіряєте відправнику цього файлу, оскільки ми не можемо перевірити, чи він не зашкодить вашому пристрою.
# This string has a special case for '1' and [other] (default). If necessary for
# your language, you can add {$count} to your translations and use the
# standard CLDR forms, or only use the form for [other] if both strings should
# be identical.
downloadTrustCheckbox =
    { $count ->
        [one] Я довіряю відправнику цього файлу
        [few] Я довіряю відправнику цих файлів
       *[many] Я довіряю відправнику цих файлів
    }
# This string has a special case for '1' and [other] (default). If necessary for
# your language, you can add {$count} to your translations and use the
# standard CLDR forms, or only use the form for [other] if both strings should
# be identical.
reportFile =
    { $count ->
        [one] Повідомити, що цей файл є підозрілим
        [few] Повідомити, що ці файли є підозрілими
       *[many] Повідомити, що ці файли є підозрілими
    }
reportDescription = Допоможіть нам зрозуміти, що відбувається. Що, на вашу думку, з цими файлами не так?
reportUnknownDescription = Перейдіть до url-адреси посилання, про яке хочете надіслати звіт, та натисніть “{ reportFile }”.
reportButton = Надіслати звіт
reportReasonMalware = Ці файли містять зловмисне програмне забезпечення або є частиною фішинг-атаки.
reportReasonPii = Ці файли містять мої особисті дані.
reportReasonAbuse = Ці файли містять незаконний або образливий вміст.
reportReasonCopyright = Щоб повідомити про порушення авторських прав або торговельних марок, скористайтеся настановами з <a>цієї сторінки</a>.
reportedTitle = Звіт про файли надіслано
reportedDescription = Дякуємо. Ми отримали ваш звіт про ці файли.
