#
# (C) Tenable Network Security, Inc.
#

# better URL in solution, preserving old:
#http://www.apple.com/downloads/macosx/apple/securityupdate__2004-05-03_(10_3_3_Client).html
#http://www.apple.com/downloads/macosx/apple/securityupdate_2004-05-03_(10_2_8_Client).html
#http://www.apple.com/downloads/macosx/apple/securityupdate_2004-05-03_(10_2_8_Server).html
#http://www.apple.com/downloads/macosx/apple/securityupdate.html
               
if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(12518);
 script_version ("$Revision: 1.8 $");
 script_cve_id(
   "CVE-2004-0020",
   "CVE-2004-0113",
   "CVE-2004-0155",
   "CVE-2004-0174",
   "CVE-2004-0392",
   "CVE-2004-0403", 
   "CVE-2004-0428",
   "CVE-2004-0430"
 );
 script_xref(name:"OSVDB", value:"4182");
 script_xref(name:"OSVDB", value:"4382");
 script_xref(name:"OSVDB", value:"4383");
 script_xref(name:"OSVDB", value:"5008");
 script_xref(name:"OSVDB", value:"5491");
 script_xref(name:"OSVDB", value:"5762");
 script_xref(name:"OSVDB", value:"5893");
 script_xref(name:"OSVDB", value:"6537");

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2004-05-03)");
 script_summary(english:"Check for Security Update 2004-05-03");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote host is missing a Mac OS X update that fixes a security\n",
     "issue."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is missing Security Update 2004-05-03.\n\n",
     "This security update includes updates for AFP Server, CoreFoundation,\n",
     "and IPSec.\n\n",
     "It also includes Security Update 2004-04-05, which includes updates\n",
     "for CUPS, libxml2, Mail, and OpenSSL.\n\n",
     "For Mac OS X 10.2.8, it also includes updates for Apache 1.3,\n",
     "cd9660.util, Classic, CUPS, Directory Services, DiskArbitration,\n",
     "fetchmail, fs_usage, gm4, groff, Mail, OpenSSL, Personal File Sharing,\n",
     "PPP, rsync, Safari, System Configuration, System Initialization, and\n",
     "zlib.\n\n",
     "This update fixes various issues which may allow an attacker to\n",
     "execute arbitrary code on the remote host."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://support.apple.com/kb/HT1646"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Install Security Update 2004-05-03."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"MacOS X Local Security Checks");

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");
os    = get_kb_item("Host/MacOSX/Version");
if ( egrep(pattern:"Mac OS X 10\.3.* Server", string:os) ) exit(0);

# MacOS X 10.2.8 and 10.3.3 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.3\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecUpd2004-05-03", string:packages) ) security_hole(0);
  else {
	set_kb_item(name:"CVE-2004-0174", value:TRUE);
	set_kb_item(name:"CVE-2003-0020", value:TRUE);
	set_kb_item(name:"CVE-2004-0079", value:TRUE);
	set_kb_item(name:"CVE-2004-0081", value:TRUE);
	set_kb_item(name:"CVE-2004-0112", value:TRUE);
	}
}
