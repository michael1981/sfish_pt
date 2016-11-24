#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(12520);
 script_version ("$Revision: 1.11 $");

 script_cve_id("CVE-2004-0538", "CVE-2004-0539");
 script_bugtraq_id(10486);
 script_xref(name:"IAVA", value:"2004-b-0008");
 script_xref(name:"OSVDB", value:"8432");
 script_xref(name:"OSVDB", value:"8433");

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2004-06-07)");
 script_summary(english:"Check for Security Update 2004-06-07");
 
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
     "The remote host is missing Security Update 2004-06-07.  This\n",
     "security update includes fixes for the following components :\n\n",
     "  DiskImages\n",
     "  LaunchServices\n",
     "  Safari\n",
     "  Terminal\n\n",
     "This update fixes a security problem which may allow an attacker\n",
     "to execute arbitrary commands the on the remote host by abusing\n",
     "of a flaw in Safari and the components listed above. To exploit\n",
     "this flaw, an attacker would need to set up a rogue web site with\n",
     "malformed HTML links, and lure the user of the remote host into\n",
     "visiting them."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://support.apple.com/kb/HT1646"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Install Security Update 2004-06-07."
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

#

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");
# MacOS X 10.2.x and 10.3.x only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.4\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecUpd2004-06-07", string:packages) ) security_warning(0);
}
