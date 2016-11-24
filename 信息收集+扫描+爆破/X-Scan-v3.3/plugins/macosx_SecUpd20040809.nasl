#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(14242);
 script_version ("$Revision: 1.8 $");
 script_cve_id(
   "CVE-2002-1363",
   "CVE-2004-0421",
   "CVE-2004-0597",
   "CVE-2004-0598",
   "CVE-2004-0599"
 );
 script_bugtraq_id(10857);
 script_xref(name:"OSVDB", value:"5726");
 script_xref(name:"OSVDB", value:"7191");
 script_xref(name:"OSVDB", value:"8312");
 script_xref(name:"OSVDB", value:"8313");
 script_xref(name:"OSVDB", value:"8314");
 script_xref(name:"OSVDB", value:"8315");
 script_xref(name:"OSVDB", value:"8316");
 script_xref(name:"OSVDB", value:"8326");

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2004-08-09)");
 script_summary(english:"Check for Security Update 2004-08-09");
 
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
     "The remote host is missing Security Update 2004-08-09.\n\n",
     "libpng is a library used for manipulating graphics files.  Several\n",
     "buffer overflows have been discovered in libpng.  A remote attacker\n",
     "could exploit these vulnerabilities by tricking a user into opening\n",
     "a maliciously crafted PNG file, resulting in the execution of\n",
     "arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://support.apple.com/kb/HT1646"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Install Security Update 2004-08-09."
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
  if ( ! egrep(pattern:"^SecUpd2004-08-09", string:packages) ) security_warning(0);
}
