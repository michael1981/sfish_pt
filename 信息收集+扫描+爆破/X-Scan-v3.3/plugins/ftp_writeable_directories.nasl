#
# (C) Tenable Network Security, Inc.
# 


include("compat.inc");


if(description)
{
 script_id(19782);
 script_version ("$Revision: 1.10 $");
 script_xref(name:"OSVDB", value:"76");
 
 script_name(english:"FTP Writable Directories");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote FTP server contains world-writable directories."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "By crawling through the remote FTP server, Nessus discovered several\n",
     "directories were marked as being world-writable.\n\n",
     "This could have several negative impacts:\n\n",
     "   * Temporary file uploads are sometimes immediately available to",
     "     all anonymous users, allowing the FTP server to be used as",
     "     a 'drop' point. This may faciliate trading copyrighted,",
     "     pornographic or questionable material.\n\n",
     "   * A user may be able to upload large files that consume disk",
     "     space, resulting in a denial of service condition.\n\n",
     "   * A user can upload a malicious program. If an administrator",
     "     routinely checks the 'incoming' directory, they may load a",
     "     document or run a program that exploits a vulnerability",
     "     in client software." 
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:string(
     "Configure the remote FTP directories so that they are not world-\n",
     "writable."
   )
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P"
 );
 script_end_attributes();

 script_summary(english:"Checks for FTP directories which are world-writable");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#

include("ftp_func.inc");
include("misc_func.inc");
include("global_settings.inc");

global_var CheckedDir;
global_var WriteableDirs;
global_var Mode;
global_var Saved_in_KB;
global_var MODE_CHECK_PERM, MODE_WRITE;


function crawl_dir(socket, directory, level )
{
 local_var port, soc2, r, dirs,array, dir, sep, str, dirname;

 if ( level > 20 ) return 0;

 if ( directory[strlen(directory) - 1] == "/" )
	sep = "";
 else
	sep = "/";

 if ( CheckedDir[directory] ) return 0;
 port = ftp_pasv(socket:socket);
 if (! port ) return 0;
 soc2 = open_sock_tcp(port);
 if (! soc2 ) return 0;
 dirs = make_list();

 if ( Mode == MODE_WRITE )
	{
	 str = "Nessus" + rand_str(length:8);
	 send(socket:socket, data:'MKD ' + directory + sep + str  + '\r\n');
	 r = ftp_recv_line(socket:socket);
	 if ( r[0] == '2' )
		{
		WriteableDirs[directory] = 1;
		send(socket:socket, data:'RMD ' + directory + sep + str + '\r\n');
	 	r = ftp_recv_line(socket:socket);
		if ( ! Saved_in_KB ) {
			replace_kb_item(name:"ftp/writeable_dir", value:directory);
			set_kb_item(name:"ftp/tested_writeable_dir", value:directory);
			Saved_in_KB ++;
			}
		}
	}

 send(socket:socket, data:'LIST ' + directory + '\r\n');
 CheckedDir[directory] = 1;

 r = ftp_recv_line(socket:socket);
 if ( r[0] != '1' ) {
	 close(soc2);
	 return 0;
	}

 while ( TRUE )
 {
  r = recv_line(socket:soc2, length:4096);
  if ( ! r ) break;
  if ( r[0] == 'd' )
	{
	 array = eregmatch(pattern:"([drwxtSs-]*) *([0-9]*) ([0-9]*) *([^ ]*) *([0-9]*) ([^ ]*) *([^ ]*) *([^ ]*) (.*)", string:chomp(r));
         if ( max_index(array) >= 9 )
         {
	 if ( Mode == MODE_CHECK_PERM )
		{
		 if ( array[1] =~ "^d.......w." )
			{
			 WriteableDirs[directory + sep + array[9]] = 1;
			 if ( ! Saved_in_KB ) {
				replace_kb_item(name:"ftp/writeable_dir", value:directory + sep + array[9]);
				set_kb_item(name:"ftp/tested_writeable_dir", value:directory);
				Saved_in_KB ++;
				}
			}		 
		}
         if ( array[9] != "." && array[9] != ".." )
	   dirs = make_list(dirs, directory + sep + array[9]);
	 }
	}
	 else if ( " <DIR> " >< r )
	 {
	  dirname = ereg_replace(pattern:".* <DIR> *(.*)$", replace:"\1", string:chomp(r));
	  if( dirname != r ) dirs = make_list(dirs, directory + sep + dirname);
	 }
  }
 close(soc2);
 r = recv_line(socket:socket, length:4096);
 foreach dir ( dirs )
 {
   crawl_dir(socket:socket, directory:dir, level:level + 1 );
 }
 return 0;
} 
 


port = get_kb_item("Services/ftp");
if ( ! get_kb_item("ftp/anonymous") ) exit(0);
if ( ! port ) port = 21;
if ( ! get_port_state(port) ) exit(0);

MODE_WRITE 		= 1;
MODE_CHECK_PERM 	= 2;


if ( safe_checks() )
 Mode = MODE_CHECK_PERM;
else 
 Mode  = MODE_WRITE;

login = "anonymous";
pwd   = "joe@";

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
if ( ! ftp_authenticate(socket:soc, user:login, pass:pwd) ) exit(0);


port2 = ftp_pasv(socket:soc);
if ( ! port2 ) exit(1, "Could not negotiate a passive port");
soc2 =  open_sock_tcp(port2);
if ( ! soc2 ) exit(1, "Could not connect to passive port " + port2);
send(socket:soc, data:'LIST .\r\n');
r = ftp_recv_line(socket:soc);
if ( r =~  "^1" ) 
{
dir = ftp_recv_listing(socket:soc2);
close(soc2);
if ( " <DIR> " >< dir ) Mode = MODE_WRITE;
}
r = ftp_recv_line(socket:soc);



crawl_dir(socket:soc, directory:"/", level:0 );
ftp_close(socket:soc);

if ( isnull(WriteableDirs) ) exit(0);

foreach dir ( keys(WriteableDirs) )
 {
  report += ' - ' + dir + '\n';
 }

if ( report )
{
 security_warning(port:port, extra:'\n'+report);
}
