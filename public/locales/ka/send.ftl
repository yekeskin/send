# Send is a brand name and should not be localized.
title = Send
importingFile = გადმოტანა...
encryptingFile = დაშიფვრა...
decryptingFile = გაშიფვრა...
downloadCount =
    { $num ->
        [one] 1 ჩამოტვირთვა
       *[other] { $num } ჩამოტვირთვა
    }
timespanHours =
    { $num ->
        [one] 1 საათი
       *[other] { $num } საათი
    }
copiedUrl = ასლი აღებულია!
unlockInputPlaceholder = პაროლი
unlockButtonLabel = გახსნა
downloadButtonLabel = ჩამოტვირთვა
downloadFinish = ჩამოტვირთვა დასრულდა
fileSizeProgress = ({ $partialSize } { $totalSize }-იდან)
sendYourFilesLink = გამოცადეთ Send
errorPageHeader = რაღაც ხარვეზია!
fileTooBig = ფაილი ზედმეტად დიდია. უნდა იყოს { $size } ზომაზე ნაკლები.
linkExpiredAlt = ბმული ვადაგასულია
notSupportedHeader = თქვენი ბრაუზერი არაა მხარდაჭერილი.
notSupportedLink = რატომ არაა ჩემი ბრაუზერი მხარდაჭერილი?
notSupportedOutdatedDetail = სამწუხაროდ, Firefox-ის ამ ვერსიას არ გააჩნია ის ტექნოლოგია, რომელიც აუცილებელია Send-ის მუშაობისთვის. გესაჭიროებათ, ბრაუზერის განახლება.
updateFirefox = Firefox-ის განახლება
deletePopupCancel = გაუქმება
deleteButtonHover = წაშლა
footerLinkLegal = სამართლებრივი საკითხები
footerLinkPrivacy = პირადულობა
footerLinkCookies = ფუნთუშები
passwordTryAgain = პაროლი არასწორია. სცადეთ ხელახლა.
javascriptRequired = Send საჭიროებს JavaScript-ს
whyJavascript = რატომ საჭიროებს Send JavaScript-ს?
enableJavascript = გთხოვთ ჩართოთ JavaScript და სცადოთ ხელახლა.
# A short representation of a countdown timer containing the number of hours and minutes remaining as digits, example "13h 47m"
expiresHoursMinutes = { $hours }სთ { $minutes }წთ
# A short representation of a countdown timer containing the number of minutes remaining as digits, example "56m"
expiresMinutes = { $minutes }წთ
# A short status message shown when the user enters a long password
maxPasswordLength = პაროლის დაშვებული ზომა: { $length }
# A short status message shown when there was an error setting the password
passwordSetError = ამ პაროლის დაყენება ვერ ხერხდება

## Send version 2 strings

# Send, Send, Firefox, Mozilla are proper names and should not be localized
-send-brand = Send
-send-short-brand = Send
-firefox = Firefox
-mozilla = Mozilla
introTitle = ფაილის გაზიარება მარტივად, დაცულად
introDescription = { -send-brand } საშუალებას გაძლევთ გააზიაროთ ფაილები გამჭოლი დაშიფვრითა და ბმულით, რომელიც გარკვეული დროის შემდეგ თავისთავად გაუქმდება. ასე რომ, რასაც გააზიარებთ იქნება საიდუმლო და არც ინტერნეტში არ დარჩება სამუდამოდ.
notifyUploadEncryptDone = თქვენი ფაილი დაშიფრულია და მზადაა გასაგზავნად
# downloadCount is from the downloadCount string and timespan is a timespanMinutes string. ex. 'Expires after 2 downloads or 25 minutes'
archiveExpiryInfo = ვადის გასვლამდე დარჩენილია { $downloadCount } ან { $timespan }
timespanMinutes =
    { $num ->
        [one] 1 წუთი
       *[other] { $num } წუთი
    }
timespanDays =
    { $num ->
        [one] 1 დღე
       *[other] { $num } დღე
    }
timespanWeeks =
    { $num ->
        [one] 1 კვირა
       *[other] { $num } კვირა
    }
fileCount =
    { $num ->
        [one] 1 ფაილი
       *[other] { $num } ფაილი
    }
# byte abbreviation
bytes = ბ
# kibibyte abbreviation
kb = კბ
# mebibyte abbreviation
mb = მბ
# gibibyte abbreviation
gb = გბ
# localized number and byte abbreviation. example "2.5MB"
fileSize = { $num } { $units }
# $size is the size of the file, displayed using the fileSize message as format (e.g. "2.5MB")
totalSize = სულ ზომა: { $size }
# the next line after the colon contains a file name
copyLinkDescription = ბმულის ასლი ფაილის გასაზიარებლად:
copyLinkButton = ბმულის ასლი
downloadTitle = ფაილების ჩამოტვირთვა
downloadDescription = ფაილი გაზიარებულია { -send-brand }-ის საშუალებით, გამჭოლი დაშიფვრითა და ვადიანი ბმულით.
trySendDescription = გამოსცადეთ { -send-brand }, ფაილების გაზიარება მარტივად, დაცულად.
# count will always be > 10
tooManyFiles =
    { $count ->
        [one] მხოლოდ 1 ფაილი შეიძლება აიტვირთოს ერთ ჯერზე.
       *[other] მხოლოდ { $count } ფაილი შეიძლება აიტვირთოს ერთ ჯერზე.
    }
# count will always be > 10
tooManyArchives =
    { $count ->
        [one] მხოლოდ 1 არქივია დაშვებული.
       *[other] მხოლოდ { $count } არქივია დაშვებული.
    }
expiredTitle = ბმული ვადაგასულია.
notSupportedDescription = { -send-brand } არ იმუშავებს ამ ბრაუზერთან. { -send-short-brand } საუკეთესოდ მუშაობს ახალ  -ზე და აგრეთვე უმეტესი ბრაუზერების უახლეს ვერსიებზე.
downloadFirefox = ჩამოტვირთეთ  
legalTitle = { -send-short-brand } პირადულობის განაცხადი
legalDateStamp = ვერსია 1.0, დათარიღებული 12 მარტით, 2019
# A short representation of a countdown timer containing the number of days, hours, and minutes remaining as digits, example "2d 11h 56m"
expiresDaysHoursMinutes = { $days } დღე { $hours } სთ { $minutes } წთ
addFilesButton = ფაილების შერჩევა ასატვირთად
trustWarningMessage = დარწმუნდით, რომ ენდობით მიმღებს, სანამ მნიშვნელოვან მონაცემებს გაუზიარებთ.
uploadButton = ატვირთვა
# the first part of the string 'Drag and drop files or click to send up to 1GB'
dragAndDropFiles = გადმოიტანეთ და მოათავსეთ ფაილები
# the second part of the string 'Drag and drop files or click to send up to 1GB'
# $size is the size of the file, displayed using the fileSize message as format (e.g. "2.5MB")
orClickWithSize = ან დაწკაპეთ გასაგზავნად { $size }-მდე
addPassword = პაროლით დაცვა
emailPlaceholder = შეიყვანეთ ელფოსტა
# $size is the size of the file, displayed using the fileSize message as format (e.g. "2.5MB")
signInSizeBump = შედით ანგარიშზე, რომ გაგზავნოთ { $size }-მდე
signInOnlyButton = შესვლა
accountBenefitTitle = შექმენით  -ანგარიში ან შედით
# $size is the size of the file, displayed using the fileSize message as format (e.g. "2.5MB")
accountBenefitLargeFiles = გააზიარეთ ფაილები { $size }-მდე
accountBenefitDownloadCount = გაუზიარეთ ფაილები მეტ ხალხს
accountBenefitTimeLimit =
    { $count ->
        [one] დატოვეთ ფაილები 1 დღემდე
       *[other] დატოვეთ ფაილები { $count } დღემდე
    }
accountBenefitSync = მართეთ გაზიარებული ფაილები ნებისმიერი მოწყობილობიდან
accountBenefitMoz = გაეცანით { -mozilla }-ს სხვა მომსახურებებს
signOut = გამოსვლა
okButton = კარგი
downloadingTitle = მიმდინარეობს ჩამოტვირთვა
noStreamsWarning = ამ ბრაუზერმა, შესაძლოა ვერ მოახერხოს ასეთი დიდი ფაილის გაშიფვრა.
noStreamsOptionCopy = ბმულის ასლის აღება სხვა ბრაუზერში გასახსნელად
noStreamsOptionFirefox = სცადეთ ჩვენი რჩეული ბრაუზერი
noStreamsOptionDownload = განაგრძეთ ამ ბრაუზერით
downloadFirefoxPromo = { -send-short-brand }-ს წარმოგიდგინეთ უახლესი  .
# the next line after the colon contains a file name
shareLinkDescription = ფაილის ბმულის გაზიარება:
shareLinkButton = ბმულის გაზიარება
# $name is the name of the file
shareMessage = ჩამოტვირთეთ „{ $name }“ { -send-brand }-ით: ფაილების გაზიარება მარტივად, უსაფრთხოდ
trailheadPromo = გზა, თქვენი პირადულობის დასაცავად. შემოუერთდით Firefox-ს.
learnMore = იხილეთ ვრცლად.
downloadFlagged = ბმული გაუქმებულია, მომსახურების პირობების დარღვევის გამო.
downloadConfirmTitle = კიდევ ერთი რამ
downloadConfirmDescription = დარწმუნდით, რომ სანდოა პირი, ვინც ეს ფაილი გამოგიგზავნათ, რადგან ჩვენ ვერ დაგპირდებით, რომ არ დააზიანებს თქვენს მოწყობილობას.
# This string has a special case for '1' and [other] (default). If necessary for
# your language, you can add {$count} to your translations and use the
# standard CLDR forms, or only use the form for [other] if both strings should
# be identical.
downloadTrustCheckbox =
    { $count ->
        [one] ვენდობი პირს, რომელმაც ეს ფაილი გამომიგზავნა
       *[other] ვენდობი პირს, რომელმაც ეს ფაილები გამომიგზავნა
    }
# This string has a special case for '1' and [other] (default). If necessary for
# your language, you can add {$count} to your translations and use the
# standard CLDR forms, or only use the form for [other] if both strings should
# be identical.
reportFile =
    { $count ->
        [one] მოხსენება, საეჭვო ფაილზე
       *[other] მოხსენება, საეჭვო ფაილებზე
    }
reportDescription = დაგვეხმარეთ გარკვევაში. თქვენი აზრით, რა ფაილებია?
reportUnknownDescription = გთხოვთ გადახვიდეთ ბმულზე, რომლზეც გსურთ გვაცნობოთ და დაწკაპეთ „{ reportFile }“.
reportButton = მოხსენება
reportReasonMalware = ეს ფაილები შეიცავს მავნე კოდს ან თაღლითური შეტევის ნაწილია.
reportReasonPii = ეს ფაილები შეიცავს ვინაობის ამსახველ მასალას ჩემზე.
reportReasonAbuse = ეს ფაილები შეიცავს უკანონო ან შეურაცხმყოფელ მასალას.
reportReasonCopyright = საავტორო უფლებებთან ან სავაჭრო ნიშნებთან დაკავშირებულ დარღვევებზე მოხსენებისთვის, გთხოვთ იხილოთ განმარტებითი მითითებები <a>ამ გვერდზე</a>.
reportedTitle = ფაილებზე მოხსენება გაგზავნილია
reportedDescription = გმადლობთ. მივიღეთ თქვენი მოხსენება, ამ ფაილებზე.
