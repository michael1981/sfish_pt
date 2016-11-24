#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
# This script is released under the GNU GPLv2
#
# Changes by Tenable:
# - Revised plugin title (2/04/2009)


include("compat.inc");

if(description)
{
 script_id(14302);
 script_cve_id("CVE-1999-0081");
 script_xref(name:"OSVDB", value:"8717");
 script_version ("$Revision: 1.7 $");
 
 script_name(english:"WU-FTPD rnfr File Overwrite");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server has a file overwrite vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote WU-FTPD server seems to be vulnerable to a remote flaw.

This version contains a flaw that may allow a malicious user to overwrite 
arbitrary files.  The issue is triggered when an attacker sends a specially 
formatted rnfr command.  This flaw will allow a remote attacker to overwrite
any file on the system.

*** Nessus solely relied on the banner of the remote server
*** to issue this warning, so it may be a false positive." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WU-FTPD 2.4.2 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N" );

script_end_attributes();

		    
 script_summary(english:"Checks the banner of the remote WU-FTPD server");
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

#login = get_kb_item("ftp/login");
#pass  = get_kb_item("ftp/password");

port = get_kb_item("Services/ftp");
if(!port)
	port = 21;
if (! get_port_state(port)) 
	exit(0);

banner = get_ftp_banner(port: port);
if( banner == NULL ) 
	exit(0);

if(egrep(pattern:".*wu-(2\.([0-3]\.|4\.[01])).*", string:banner))
	security_hole(port);

