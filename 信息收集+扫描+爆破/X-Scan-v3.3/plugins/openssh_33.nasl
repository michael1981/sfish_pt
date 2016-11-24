#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# also covers CVE-2002-0765


include("compat.inc");

if(description)
{
 script_id(11031);
 script_version ("$Revision: 1.23 $");

 script_cve_id("CVE-2002-0639", "CVE-2002-0640");
 script_bugtraq_id(5093);
 script_xref(name:"IAVA", value:"2002-t-0011");
 script_xref(name:"OSVDB", value:"839");
 script_xref(name:"OSVDB", value:"6245");
 
 script_name(english:"OpenSSH < 3.4 Multiple Remote Overflows");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host appears to be 
running OpenSSH version 3.4 or older. Such versions are 
reportedly affected by multiple flaws. An attacker may 
exploit these vulnerabilities to gain a shell on the remote 
system.

Note that several distribution patched this hole without 
changing the version number of OpenSSH. Since Nessus solely 
relied on the banner of the remote SSH server to perform this 
check, this might be a false positive.

If you are running a RedHat host, make sure that the command :
          rpm -q openssh-server
	  
Returns :
	openssh-server-3.1p1-6" );
 script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/preauth.adv" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 3.4 or contact your vendor for a patch" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 script_summary(english:"Checks for the remote SSH version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 if (  ! defined_func("bn_random") )
 	script_dependencie("ssh_detect.nasl");
 else
 	script_dependencie("ssh_detect.nasl", "redhat-RHSA-2002-131.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here
#

include("backport.inc"); 

if ( get_kb_item("CVE-2002-0640") ) exit(0);

port = get_kb_item("Services/ssh");
if(!port)port = 22;



banner = get_kb_item("SSH/banner/" + port ) ;
if( ! banner ) exit(0);
banner = get_backport_banner(banner:banner);
banner = tolower(banner);
if("openssh" >< banner)
{
 if(ereg(pattern:".*openssh[-_]((1\..*)|(2\..*)|(3\.([0-3](\.[0-9]*)*)))", string:banner))
	security_hole(port);
}
