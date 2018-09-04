# Project CHAINSHOT - Server side PHP scripts
Description how to set up the reproduced server side PHP scripts to be able to make a dyanmic analysis of the attack chain. Note that you need to have Adobe Flash Player ActiveX version 29.0.0.171 or earlier installed for the chain to be working. However, it seems that some older versions do not work for unknown reasons. For example, although version 11.7.700.269 triggers the exploit successfully, it does not work with the execution of subsequent malware stages.

## Step 1: Set up a local web server
For example, we have used [XAMPP](https://www.apachefriends.org/) which makes it very easy to create a local Apache server. After the installation, add the following data to the file **httpd-vhosts.conf** to create a virtual host of the attacker server. For example:

```
NameVirtualHost *:80

<VirtualHost *:80>
ServerName people.dohabayt.com
ServerAlias www.people.dohabayt.com
ServerAdmin email@people.dohabayt.com
DocumentRoot "C:/xampp/htdocs/"
</VirtualHost>
```

You might need to change the domain depending on which Excel document you have. It can be found in the Shockwave Flash ActiveX object properties in the document. At last, add the following data to the Windows **hosts** file to redirect the DNS request to the local web werver. For example:

```
127.0.0.1           people.dohabayt.com
```

Again, the domain name might be different, as previously described.

## Step 2: Set up the infrastructure
Copy the provided folders along with the PHP scripts into the **C:/xampp/htdocs/** directory. Depending on the MD5 like token used in the Excel document, you might need to change the string **65f6434672f90eba68b96530172db71a** for the PHP script and directories accordingly. At last, you need to put the Flash downloader, the Flash exploit and the shellcode payload in the approprite directories and change the file name in the PHP scripts accordingly (see comments inside the PHP files). Put the files into the following folders:

| Directory                                   | File to put in    |
|:------------------------------------------- |:----------------- |
| /songs/                                     | Flash downloader  |
| /photos/doc/                                | Flash exploit     |
| /download/65f6434672f90eba68b96530172db71a/ | Shellcode payload |

We have also created an example for the status messages PHP script (see **/stab/** directory) which is however optional. Neither the Flash downloader nor the Flash exploit check if the messages were sent successfully. However, the **/log/** and **/home/** directories are necessary as the malware checks for the response data. We haven't figured out what gets send back encrypted, but believe it's a command to execute the SecondStageDropper.dll.

## Step 3: Have fun
Now that everything is set up you can start the web server, open the Excel document and capture the network traffic and dynamically analyse the single stages.