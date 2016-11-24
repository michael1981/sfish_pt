#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(15420);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2004-0921", "CVE-2004-0922", "CVE-2004-0558", "CVE-2004-0923", "CVE-2004-0924", "CVE-2004-0925", 
               "CVE-2004-0926", "CVE-2004-0927");
 script_bugtraq_id(11322, 11324, 11323, 11207);
 script_xref(name:"OSVDB", value:"9995");
 script_xref(name:"OSVDB", value:"10496");
 script_xref(name:"OSVDB", value:"10497");
 script_xref(name:"OSVDB", value:"10498");
 script_xref(name:"OSVDB", value:"10499");
 script_xref(name:"OSVDB", value:"10500");
 script_xref(name:"OSVDB", value:"10501");
 script_xref(name:"OSVDB", value:"10502");
 script_xref(name:"OSVDB", value:"11048");
 script_xref(name:"OSVDB", value:"11203");
 script_xref(name:"IAVA", value:"2004-t-0030");

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2004-09-30)");
 script_summary(english:"Check for Security Update 2004-09-30");
 
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
     "The remote host is missing Security Update 2004-09-30.  This security\n",
     "update contains a number of fixes for the following programs :\n\n",
     "  - AFP Server\n",
     "  - CUPS\n",
     "  - NetInfoManager\n",
     "  - postfix\n",
     "  - QuickTime\n",
     "  - ServerAdmin\n\n",
     "These programs have multiple vulnerabilities which may allow a\n",
     "remote attacker to execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://support.apple.com/kb/HT1646"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Install Security Update 2004-09-03."
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

#

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");
# MacOS X 10.2.8, 10.3.5 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.5\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecUpd(Srvr)?2004-09-30", string:packages) ) security_hole(0);
}
