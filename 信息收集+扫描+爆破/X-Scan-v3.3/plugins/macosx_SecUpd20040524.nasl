#
# (C) Tenable Network Security, Inc.
#

# URLs dead
#"macosx_SecUpd20040503.nasl"
#http://www.apple.com/downloads/macosx/apple/securityupdate__2004-05-24_(10_3_3).html
#http://www.apple.com/downloads/macosx/apple/securityupdate_2004-05-24_(10_2_8).html

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(12519);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2004-0485", "CVE-2004-0486");
 script_xref(name:"OSVDB", value:"6184");
 script_xref(name:"OSVDB", value:"6536");

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2004-05-24)");
 script_summary(english:"Check for Security Update 2004-05-24");
 
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
     "The remote host is missing Security Update 2004-05-24.  This security\n",
     "update includes fixes for the following components :\n\n",
     "  HelpViewer\n",
     "  Terminal\n\n",
     "This update fixes security issues which may allow an attacker to\n",
     "execute arbitrary commands on the remote host by exploiting a flaw\n",
     "in Safari and the components listed above.  A remote attacker could\n",
     "exploit this flaw by tricking a user into visiting a malicious website."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://support.apple.com/kb/HT1646"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Install Security Update 2004-05-24."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P"
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
# MacOS X 10.2.8 and 10.3.3 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.3\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecUpd2004-05-24", string:packages) ) security_warning(0);
}
