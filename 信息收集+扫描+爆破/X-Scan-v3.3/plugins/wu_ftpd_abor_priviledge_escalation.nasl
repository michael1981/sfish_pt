#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
# Ref: David Greenman <dg at root dot com>
# This script is released under the GNU GPLv2
#
# Changes by Tenable:
# - Revised plugin title (2/04/2009)


include("compat.inc");

if(description)
{
 script_id(14301);
 script_cve_id("CVE-1999-1326");
 script_xref(name:"OSVDB", value:"8718");
 script_version ("$Revision: 1.8 $");
 
 script_name(english:"WU-FTPD ABOR Command Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server seems to be vulnerable to a remote privilege
escalation." );
 script_set_attribute(attribute:"description", value:
"The version of WU-FTPD running on the remote host contains a flaw that
may allow a malicious user to gain access to unauthorized privileges. 

Specifically, there is a flaw in the way that the server handles
an ABOR command after a data connection has been closed.  The 
flaw is within the dologout() function and proper exploitation
will give the remote attacker the ability to execute arbitrary 
code as the 'root' user.

This flaw may lead to a loss of confidentiality and/or integrity.

*** Nessus solely relied on the banner of the remote server
*** to issue this warning, so it may be a false positive." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/1997_1/0007.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/1997_1/0014.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Wu-FTPd 2.4.2 or newer" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N" );
		
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
	security_warning(port);
