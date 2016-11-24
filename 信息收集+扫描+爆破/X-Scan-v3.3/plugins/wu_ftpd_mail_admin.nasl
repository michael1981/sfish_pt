#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
# Ref: Adam Zabrocki <pi3ki31ny@wp.pl>
# This script is released under the GNU GPLv2
#
# Changes by Tenable:
# - Revised plugin title (2/04/2009)


include("compat.inc");

if(description)
{
 script_id(14371);
 script_cve_id("CVE-2003-1327");
 script_bugtraq_id(8668);
 script_xref(name:"OSVDB", value:"2594");
 script_version ("$Revision: 1.10 $");
 
 script_name(english:"WU-FTPD MAIL_ADMIN Function Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"Th remote Wu-FTPD server fails to properly check bounds on a pathname
when Wu-Ftpd is compiled with MAIL_ADMIN enabled resulting in a buffer
overflow.  With a specially crafted request, an attacker can possibly
execute arbitrary code as the user Wu-Ftpd runs as (usually root)
resulting in a loss of integrity, and/or availability. 

It should be noted that this vulnerability is not present within the
default installation of Wu-Ftpd. 

The server must be configured using the 'MAIL_ADMIN' option to notify
an administrator when a file has been uploaded. 

*** Nessus solely relied on the banner of the remote server
*** to issue this warning, so it may be a false positive." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2003-09/0348.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Wu-FTPd 2.6.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
		
script_end_attributes();

		    
 
 script_summary(english:"Checks the banner of the remote wu-ftpd server");
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
		  
 script_dependencie("find_service1.nasl", "ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/login", "ftp/wuftpd");
 script_require_ports("Services/ftp", 21);
  
 exit(0);
}

#
# The script code starts here : 
#
include("ftp_func.inc");
include("backport.inc");


port = get_kb_item("Services/ftp");
if(!port) port = 21;
if (! get_port_state(port)) exit(0);

banner = get_backport_banner(banner:get_ftp_banner(port: port));
if( banner == NULL ) exit(0);
if(egrep(pattern:".*wu-2\.6\.[012].*", string:banner)) security_hole(port);

