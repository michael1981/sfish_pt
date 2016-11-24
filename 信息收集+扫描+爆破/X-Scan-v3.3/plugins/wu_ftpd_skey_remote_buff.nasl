#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
# Ref: Michal Zalewski & Michael Hendrickx
# This script is released under the GNU GPLv2
#
# Changes by Tenable:
# - Revised plugin title (2/04/2009)


include("compat.inc");

if(description)
{
 script_id(14372);
 script_bugtraq_id(8893);
 script_cve_id("CVE-2004-0185");
 script_xref(name:"OSVDB", value:"2715");
 script_xref(name:"RHSA", value:"RHSA-2004:096-09");
 script_xref(name:"DSA", value:"DSA-457-1");
 script_version ("$Revision: 1.9 $");
 
 script_name(english:"WU-FTPD S/KEY Authentication ftpd.c skey_challenge Function Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server seems to be vulnerable to a remote buffer overflow." );
 script_set_attribute(attribute:"description", value:
"This version of WU-FTPD contains a remote overflow if s/key support is enabled. 
The skey_challenge function fails to perform bounds checking on the 
name variable resulting in a buffer overflow. 
With a specially crafted request, an attacker can execute arbitrary 
code resulting in a loss of integrity and/or availability.

It appears that this vulnerability may be exploited prior to authentication.
It is reported that S/Key support is not enabled by default, 
though some operating system distributions which ship WU-FTPD may have it 
enabled.

*** Nessus solely relied on the banner of the remote server
*** to issue this warning, so it may be a false positive." );
 script_set_attribute(attribute:"see_also", value:"http://www.securiteam.com/unixfocus/6X00Q1P8KC.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WU-FTPD 2.6.3 when available or disable SKEY or apply the
patches available at http://www.wu-ftpd.org" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
		
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
if(!port)
	port = 21;
if (! get_port_state(port)) 
	exit(0);


banner = get_backport_banner(banner:get_ftp_banner(port: port));
if( banner == NULL ) 
	exit(0);

if(egrep(pattern:".*wu-(2\.(5\.|6\.[012])).*", string:banner))
	security_hole(port);
