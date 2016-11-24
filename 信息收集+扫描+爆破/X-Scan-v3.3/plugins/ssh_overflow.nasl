#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10269);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-1999-0834");
 script_bugtraq_id(843);
 script_xref(name:"OSVDB", value:"213");
 
 script_name(english:"SSH RSAREF Library Multiple Functions Local Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SSH server may allow execution of arbitrary code." );
 script_set_attribute(attribute:"description", value:
"The remote SSH server is version 1.2.27 or earlier. 

If this version was compiled against the RSAREF library, then it is
likely to be vulnerable to a buffer overflow that a remote attacker
could exploit to gain root privileges on the affected system. 

To determine if you compiled ssh against the RSAREF library, type 'ssh
-V' on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/1999-q4/0169.html" );
 script_set_attribute(attribute:"solution", value:
"Either re-compile ssh to avoid using the RSAREF library or upgrade to
SSH 2.x or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 script_summary(english:"Checks for the remote SSH version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencie("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here
#
include('global_settings.inc');
include('backport.inc');

if ( report_paranoia < 2 ) exit(0);

port = get_kb_item("Services/ssh");
if(!port)port = 22;


banner = get_kb_item("SSH/banner/" + port );
if ( ! banner ) exit(0);

banner = get_backport_banner(banner:banner);

if ( "openssh" >< tolower(banner) ) exit(0);

if(ereg(string:banner, pattern:"SSH-.*-1\.([0-1]|2\.([0-1]..*|2[0-7]))[^0-9]*$", icase:TRUE))security_hole(port);
