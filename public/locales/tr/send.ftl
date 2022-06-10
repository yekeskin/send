# Send is a brand name and should not be localized.
title = Send
importingFile = İçe aktarılıyor…
encryptingFile = Şifreleniyor…
decryptingFile = Şifre çözülüyor…
downloadCount = { $num } indirme
timespanHours =
    { $num ->
        [one] 1 saat
       *[other] { $num } saat
    }
copiedUrl = Kopyalandı!
unlockInputPlaceholder = Parola
unlockButtonLabel = Kilidi aç
downloadButtonLabel = İndir
downloadFinish = İndirme tamamlandı
fileSizeProgress = ({ $partialSize } / { $totalSize })
sendYourFilesLink = Send’i deneyin
errorPageHeader = Bir şeyler ters gitti!
fileTooBig = Dosyanız çok büyük. En fazla { $size } boyutunda olmalı.
linkExpiredAlt = Bağlantı zaman aşımına uğramış
notSupportedHeader = Tarayıcınız desteklenmiyor.
notSupportedLink = Tarayıcım neden desteklenmiyor?
notSupportedOutdatedDetail = Kullandığınız Firefox sürümü Send için gereken web teknolojilerini desteklemiyor. Tarayıcınızı güncellemeniz gerekiyor.
updateFirefox = Firefox’u güncelle
deletePopupCancel = Vazgeç
deleteButtonHover = Sil
footerLinkLegal = Yasal Bilgiler
footerLinkPrivacy = Gizlilik
footerLinkCookies = Çerezler
passwordTryAgain = Yanlış parola. Yeniden deneyin.
javascriptRequired = Send için JavaScript gerekir
whyJavascript = Send neden JavaScript kullanıyor?
enableJavascript = Lütfen JavaScript'i etkinleştirip yeniden deneyin.
# A short representation of a countdown timer containing the number of hours and minutes remaining as digits, example "13h 47m"
expiresHoursMinutes = { $hours } sa { $minutes } dk
# A short representation of a countdown timer containing the number of minutes remaining as digits, example "56m"
expiresMinutes = { $minutes } dk
# A short status message shown when the user enters a long password
maxPasswordLength = Maksimum parola uzunluğu: { $length }
# A short status message shown when there was an error setting the password
passwordSetError = Parola ayarlanamadı

## Send version 2 strings

# Send, Send, Firefox, Mozilla are proper names and should not be localized
-send-brand = Send
-send-short-brand = Send
-firefox = Firefox
-mozilla = Mozilla
introTitle = Basit ve gizli dosya paylaşımı
introDescription = { -send-brand } ile dosyalarınızı uçtan uca şifreleme ve otomatik olarak silinen bir bağlantıyla paylaşın. Böylece özel dosyalarınız güvenle saklanır, bir süre sonra kendi kendine silinir.
notifyUploadEncryptDone = Dosyanız şifrelendi ve gönderilmeye hazır
# downloadCount is from the downloadCount string and timespan is a timespanMinutes string. ex. 'Expires after 2 downloads or 25 minutes'
archiveExpiryInfo = { $downloadCount } veya { $timespan } sonra silinecek
timespanMinutes =
    { $num ->
        [one] 1 dakika
       *[other] { $num } dakika
    }
timespanDays =
    { $num ->
        [one] 1 gün
       *[other] { $num } gün
    }
timespanWeeks =
    { $num ->
        [one] 1 hafta
       *[other] { $num } hafta
    }
fileCount =
    { $num ->
        [one] 1 dosya
       *[other] { $num } dosya
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
totalSize = Toplam boyut: { $size }
# the next line after the colon contains a file name
copyLinkDescription = Dosyanızı paylaşmak için bağlantıyı kopyalayın:
copyLinkButton = Bağlantıyı kopyala
downloadTitle = Dosyaları indir
downloadDescription = Bu dosya { -send-brand } üzerinden paylaşıldı. Uçtan uca şifreleme ve kendiliğinden silinen bağlantı koruması { -send-brand }’de.
trySendDescription = Basit ve güvenli dosya paylaşımı için { -send-brand }’i deneyin.
# count will always be > 10
tooManyFiles =
    { $count ->
        [one] Bir kerede en fazla 1 dosya yükleyebilirsiniz.
       *[other] Bir kerede en fazla { $count } dosya yükleyebilirsiniz.
    }
# count will always be > 10
tooManyArchives =
    { $count ->
        [one] En fazla 1 arşive izin veriliyor.
       *[other] En fazla { $count } arşive izin veriliyor.
    }
expiredTitle = Bu bağlantının süresi doldu.
notSupportedDescription = { -send-brand } bu tarayıcıyı desteklemiyor. { -send-short-brand } en iyi şekilde  ’un son sürümüyle ve çoğu tarayıcının güncel sürümüyle çalışır.
downloadFirefox =  ’u indir
legalTitle = { -send-short-brand } Gizlilik Bildirimi
legalDateStamp = Sürüm 1.0, 12 Mart 2019
# A short representation of a countdown timer containing the number of days, hours, and minutes remaining as digits, example "2d 11h 56m"
expiresDaysHoursMinutes = { $days } g { $hours } sa { $minutes } dk
addFilesButton = Yüklenecek dosyaları seçin
trustWarningMessage = Hassas verileri paylaşırken alıcıya güvendiğinizden emin olun.
uploadButton = Yükle
# the first part of the string 'Drag and drop files or click to send up to 1GB'
dragAndDropFiles = Dosyaları sürükleyip bırakarak
# the second part of the string 'Drag and drop files or click to send up to 1GB'
# $size is the size of the file, displayed using the fileSize message as format (e.g. "2.5MB")
orClickWithSize = veya buraya tıklayarak { $size }’ye kadar dosyalarınızı gönderebilirsiniz
addPassword = Parola koruması ekle
emailPlaceholder = E-posta adresinizi yazın
# $size is the size of the file, displayed using the fileSize message as format (e.g. "2.5MB")
signInSizeBump = { $size }’ye kadar dosya göndermek için giriş yapın
signInOnlyButton = Giriş yap
accountBenefitTitle =   Hesabı açın veya giriş yapın
# $size is the size of the file, displayed using the fileSize message as format (e.g. "2.5MB")
accountBenefitLargeFiles = { $size } boyutlu dosyaları paylaşma
accountBenefitDownloadCount = Daha fazla kişiyle dosya paylaşma
accountBenefitTimeLimit =
    { $count ->
        [one] Bağlantıları 1 güne kadar aktif tutma
       *[other] Bağlantıları { $count } güne kadar aktif tutma
    }
accountBenefitSync = Paylaştığınız dosyaları başka cihazlardan yönetebilme
accountBenefitMoz = Diğer { -mozilla } servisleri hakkında bilgi alma
signOut = Çıkış yap
okButton = Tamam
downloadingTitle = İndiriliyor
noStreamsWarning = Bu tarayıcı bu kadar büyük bir dosyanın şifresini çözemeyebilir.
noStreamsOptionCopy = Bağlantıyı başka bir tarayıcıda açmak için kopyala
noStreamsOptionFirefox = En sevdiğimiz tarayıcıyı deneyin
noStreamsOptionDownload = Bu tarayıcıyla devam edin
downloadFirefoxPromo = { -send-short-brand }, yepyeni   tarafından sunulmaktadır.
# the next line after the colon contains a file name
shareLinkDescription = Dosyanızın bağlantısını paylaşın:
shareLinkButton = Bağlantıyı paylaş
# $name is the name of the file
shareMessage = “{ $name }” dosyasını { -send-brand } ile indirin: basit ve güvenli dosya paylaşımı
trailheadPromo = Gizliliğinizi korumanın bir yolu var. Firefox’a katılın.
learnMore = Daha fazla bilgi alın.
downloadFlagged = Bu bağlantı hizmet koşullarımızı ihlal ettiği için devre dışı bırakıldı.
downloadConfirmTitle = Bir şey daha
downloadConfirmDescription = Bu dosyayı gönderen kişiye güvendiğinizden emin olun. Dosyanın cihazınıza zarar vermeyeceğini garanti edemeyiz.
# This string has a special case for '1' and [other] (default). If necessary for
# your language, you can add {$count} to your translations and use the
# standard CLDR forms, or only use the form for [other] if both strings should
# be identical.
downloadTrustCheckbox =
    { $count ->
        [one] Bu dosyayı gönderen kişiye güveniyorum
       *[other] Bu dosyaları gönderen kişiye güveniyorum
    }
# This string has a special case for '1' and [other] (default). If necessary for
# your language, you can add {$count} to your translations and use the
# standard CLDR forms, or only use the form for [other] if both strings should
# be identical.
reportFile =
    { $count ->
        [one] Bu dosyanın şüpheli olduğunu bildir
       *[other] Bu dosyaların şüpheli olduğunu bildir
    }
reportDescription = Meseleyi anlamamıza yardımcı olun. Bu dosyalardaki sorun nedir?
reportUnknownDescription = Lütfen rapor etmek istediğiniz bağlantının adresine girip “{ reportFile }” bağlantısına tıklayın.
reportButton = Şikâyet et
reportReasonMalware = Bu dosyalar kötü amaçlı yazılım içeriyor veya kimlik avı saldırında kullanılıyor.
reportReasonPii = Bu dosyalar benim hakkımda kişisel bilgiler içeriyor.
reportReasonAbuse = Bu dosyalar yasa dışı veya istismar amaçlı içerik içeriyor.
reportReasonCopyright = Telif hakkı veya ticari marka ihlallerini bildirmek için <a>bu sayfadaki</a> adımları izlemelisiniz.
reportedTitle = Dosyalar rapor edildi
reportedDescription = Teşekkür ederiz. Bu dosyalarla ilgili şikâyetinizi aldık.
