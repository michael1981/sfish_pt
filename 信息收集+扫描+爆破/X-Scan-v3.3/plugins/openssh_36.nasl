#
# (C) Tenable Network Security, Inc.
#

# Thanks to H D Moore for his notification.

include("compat.inc");


if(description)
{
 script_id(11837);
 script_version ("$Revision: 1.24 $");

 script_cve_id("CVE-2003-0682", "CVE-2003-0693", "CVE-2003-0695");
 script_bugtraq_id(8628);
 script_xref(name:"IAVA", value:"2003-t-0020");
 script_xref(name:"OSVDB", value:"2557");
 script_xref(name:"OSVDB", value:"3456");
 script_xref(name:"RHSA", value:"RHSA-2003:279");
 script_xref(name:"SuSE", value:"SUSE-SA:2003:039");

 script_name(english:"OpenSSH < 3.7.1 Multiple Vulnerabilities");
 script_summary(english:"Checks for the remote SSH version");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote SSH service is affected by a various memory bugs."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "According to its banner, the remote SSH server is running a version of\n",
     "OpenSSH older than 3.7.1.  Such versions are vulnerable to a flaw in\n",
     "the buffer management functions that might allow an attacker to\n",
     "execute arbitrary commands on this host.\n",
     "\n",
     "An exploit for this issue is rumored to exist.\n",
     "\n",
     "Note that several distribution patched this hole without changing the\n",
     "version number of OpenSSH.  Since Nessus solely relied on the banner\n",
     "of the remote SSH server to perform this check, this might be a false\n",
     "positive. \n",
     "\n",
     "If you are running a RedHat host, make sure that the command :\n",
     "\n",
     "  rpm -q openssh-server\n",
     "\n",
     "returns :\n",
     "\n",
     "  openssh-server-3.1p1-13 (RedHat 7.x)\n",
     "  openssh-server-3.4p1-7  (RedHat 8.0)\n",
     "  openssh-server-3.5p1-11 (RedHat 9)\n"
   )
 );
 script_set_attribute(
   attribute:"see_also", 
   value:"http://marc.info/?l=openbsd-misc&m=106375452423794&w=2"
 );
 script_set_attribute(
   attribute:"see_also", 
   value:"http://marc.info/?l=openbsd-misc&m=106375456923804&w=2"
 );
 script_set_attribute(
   attribute:"solution", 
   value:string(
     "Upgrade to OpenSSH 3.7.1 or later."
   )
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 if ( ! defined_func("bn_random") )
	script_dependencie("ssh_detect.nasl");
 else
 	script_dependencie("ssh_detect.nasl", "ssh_get_info.nasl", "redhat-RHSA-2003-280.nasl", "redhat_fixes.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here
#

include("backport.inc"); 

port = get_kb_item("Services/ssh");
if(!port)port = 22;

if ( get_kb_item("CVE-2003-0682") ) exit(0);

banner = get_kb_item("SSH/banner/" + port);
if ( ! banner ) exit(0);
banner = tolower(get_backport_banner(banner:banner));
if(ereg(pattern:".*openssh[-_](([12]\..*)|(3\.[0-6].*)|(3\.7[^\.]*$))[^0-9]*", 
	string:banner)) {
		security_hole(port);
	}
