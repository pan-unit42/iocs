<?php
$gzip = "empty.gz";

// Read gzip file
if (file_exists($gzip)) {
    header('Content-Encoding: gzip');
    ob_clean();
    flush();
    readfile($gzip);
} 
else {
    die("Error: File not found.");
}
?>