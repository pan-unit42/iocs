<?php
// Put the Adobe Flash downloader in the same directory and change <AdobeFlashDownloaderNameHere> according to its name
$flash_downloader = "<AdobeFlashDownloaderNameHere>";

// Set HTTP header fields and read Adobe Flash downloader content
if (file_exists($flash_downloader)) {
    header('Content-Type: application/x-shockwave-flash');
    header('Content-Disposition: inline');
    header('Content-Transfer-Encoding: binary');
    header('Content-Length:'.filesize($flash_downloader));
    ob_clean();
    flush();
    readfile($flash_downloader);
} 
else {
    die("Error: Flash downloader not found!");
}
?>