<?php
// PHP script to put data into a file
function saveContents()
{
    $filename = $_GET["filename"];
    //echo "The filename is $filename";
    $contents = $_GET["contents"];
    //echo "The contents of the file are $contents";
    if(strlen($contents) > 0) {
        $contents = stripslashes($contents);
        $contents .= "\n";
    }
    $append   = $_GET["append"];

    $fname = "data/".$filename;
    $myfile = fopen($fname, "a+");
    if($myfile == FALSE) {
        exit("Error opening file: ".$fname);
    }
    fwrite($myfile, $contents, strlen($contents));
    fclose($myfile);

//    if(isset($append) && $append == "true") {
//       $outputFile = file_put_contents($filename, $contents, FILE_APPEND | LOCK_EX);
//       echo "The return value is (1) ".$outputFile;
//    }
//    else { 
//       $outputFile=  file_put_contents($filename, $contents, LOCK_EX);
//       echo "The return value is (2) ".$outputFile;
//    }
//    echo "Finally the contents of the file are $contents";
}
saveContents();
?>
