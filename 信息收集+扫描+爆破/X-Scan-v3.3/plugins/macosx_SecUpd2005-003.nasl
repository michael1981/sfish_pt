#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(17587);
 script_version ("$Revision: 1.11 $");

 if (NASL_LEVEL >= 3000)
 {
  script_cve_id("CVE-2002-1347", "CVE-2004-0884", "CVE-2004-1011", "CVE-2004-1012", "CVE-2004-1013",
                "CVE-2004-1015", "CVE-2004-1067", "CVE-2005-0202", "CVE-2005-0235", "CVE-2005-0340", 
                "CVE-2005-0712", "CVE-2005-0713", "CVE-2005-0715", "CVE-2005-0716");
 }
 script_bugtraq_id(6347, 12478, 12863, 13224, 13220, 13226, 13237);
 script_xref(name:"OSVDB", value:"15008");
 script_xref(name:"OSVDB", value:"15007");
 script_xref(name:"OSVDB", value:"15006");
 script_xref(name:"OSVDB", value:"15005");
 script_xref(name:"OSVDB", value:"13780");

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2005-003)");
 script_summary(english:"Check for Security Update 2005-003");
 
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
     "The remote host is missing Security Update 2005-003. This security\n",
     "update contains security fixes for the following applications :\n",
     "\n",
     "  - AFP Server\n",
     "  - Bluetooth Setup Assistant\n",
     "  - Core Foundation\n",
     "  - Cyrus IMAP\n",
     "  - Cyrus SASL\n",
     "  - Folder Permissions\n",
     "  - Mailman\n",
     "  - Safari\n",
     "\n",
     "These programs have multiple vulnerabilities which may allow a remote\n",
     "attacker to execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://support.apple.com/kb/TA22971"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Install Security Update 2005-003."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"MacOS X Local Security Checks");

 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");
# MacOS X 10.2.8, 10.3.7 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.[78]\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?2005-003", string:packages) ) security_hole(0);
	else non_vuln = 1;
}
else if ( egrep(pattern:"Darwin.* (6\.9|[0-9][0-9]\.|7\.(9\.|[0-9][0-9]\.))", string:uname) ) non_vuln = 1;

if ( non_vuln )
{
 foreach cve (make_list("CVE-2005-0340", "CVE-2005-0715", "CVE-2005-0716", "CVE-2005-0713", "CVE-2004-1011", "CVE-2004-1012", "CVE-2004-1013", "CVE-2004-1015", "CVE-2004-1067", "CVE-2002-1347", "CVE-2004-0884", "CVE-2005-0712", "CVE-2005-0202", "CVE-2005-0235" ))
	{
	set_kb_item(name:cve, value:TRUE);
	}
}
