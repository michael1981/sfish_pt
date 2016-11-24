#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if(description)
{
 script_id(14676);
 script_version ("$Revision: 1.12 $");

  script_cve_id("CVE-2004-0175", "CVE-2004-0183", "CVE-2004-0184", "CVE-2004-0361", "CVE-2004-0426", 
                "CVE-2004-0488", "CVE-2004-0493", "CVE-2004-0521", "CVE-2004-0523", "CVE-2004-0607",
                "CVE-2004-0720", "CVE-2004-0794", "CVE-2004-0821", "CVE-2004-0822", "CVE-2004-0823",
                "CVE-2004-0824", "CVE-2004-0825");
  script_bugtraq_id(9815, 9986, 10003, 10004, 10247, 10397, 11135, 11136, 11137, 11138, 11139, 11140);
  script_xref(name:"IAVA", value:"2004-t-0017");
  script_xref(name:"OSVDB", value:"4158");
  script_xref(name:"OSVDB", value:"6841");
  script_xref(name:"OSVDB", value:"7296");
  script_xref(name:"OSVDB", value:"8232");
  script_xref(name:"OSVDB", value:"9550");
  script_xref(name:"OSVDB", value:"9757");
  script_xref(name:"OSVDB", value:"9758");
  script_xref(name:"OSVDB", value:"9759");
  script_xref(name:"OSVDB", value:"9760");
  script_xref(name:"OSVDB", value:"59837");

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2004-09-07)");
 script_summary(english:"Check for Security Update 2004-09-07");
 
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
     "The remote host is missing Security Update 2004-09-07.  This security\n",
     "update fixes the following components :\n\n",
     "  - CoreFoundation\n",
     "  - IPSec\n",
     "  - Kerberos\n",
     "  - libpcap\n",
     "  - lukemftpd\n",
     "  - NetworkConfig\n",
     "  - OpenLDAP\n",
     "  - OpenSSH\n",
     "  - PPPDialer\n",
     "  - rsync\n",
     "  - Safari\n",
     "  - tcpdump\n\n",
     "These applications contain multiple vulnerabilities that may allow\n",
     "a remote attacker to execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://support.apple.com/kb/HT1646"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Install Security Update 2004-09-07."
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
# MacOS X 10.2.8, 10.3.4 and 10.3.5 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.[45]\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecUpd(Srvr)?2004-09-07", string:packages) ) security_hole(0);
}
