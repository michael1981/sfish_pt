#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if(description)
{
 script_id(18189);
 script_version ("$Revision: 1.10 $");

  script_cve_id("CVE-2004-0687", "CVE-2004-0688", "CVE-2004-1051", "CVE-2004-1307", "CVE-2004-1308",
                "CVE-2005-0342", "CVE-2005-0594", "CVE-2005-1330", "CVE-2005-1331", "CVE-2005-1332",
                "CVE-2005-1333", "CVE-2005-1335", "CVE-2005-1336", "CVE-2005-1337", "CVE-2005-1338",
                "CVE-2005-1339", "CVE-2005-1340", "CVE-2005-1341", "CVE-2005-1342", "CVE-2005-1343",
                "CVE-2005-1344");
 script_bugtraq_id(13503, 13502, 13500, 13496, 13494, 13491, 13488, 13486, 13480);
 script_xref(name:"OSVDB", value:"10026");
 script_xref(name:"OSVDB", value:"10027");
 script_xref(name:"OSVDB", value:"10028");
 script_xref(name:"OSVDB", value:"10029");
 script_xref(name:"OSVDB", value:"10030");
 script_xref(name:"OSVDB", value:"10031");
 script_xref(name:"OSVDB", value:"10032");
 script_xref(name:"OSVDB", value:"10033");
 script_xref(name:"OSVDB", value:"10034");
 script_xref(name:"OSVDB", value:"12555");
 script_xref(name:"OSVDB", value:"12556");
 script_xref(name:"OSVDB", value:"13617");
 script_xref(name:"OSVDB", value:"16071");
 script_xref(name:"OSVDB", value:"16072");
 script_xref(name:"OSVDB", value:"16073");
 script_xref(name:"OSVDB", value:"16074");
 script_xref(name:"OSVDB", value:"16075");
 script_xref(name:"OSVDB", value:"16077");
 script_xref(name:"OSVDB", value:"16078");
 script_xref(name:"OSVDB", value:"16079");
 script_xref(name:"OSVDB", value:"16080");
 script_xref(name:"OSVDB", value:"16081");
 script_xref(name:"OSVDB", value:"16082");
 script_xref(name:"OSVDB", value:"16083");
 script_xref(name:"OSVDB", value:"16084");
 script_xref(name:"OSVDB", value:"16085");

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2005-005)");
 script_summary(english:"Check for Security Update 2005-005");

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
     "The remote host is missing Security Update 2005-005. This security\n",
      "update contains fixes for the following applications :\n",
      "\n",
      "  - Apache\n",
      "  - AppKit\n",
      "  - AppleScript\n",
      "  - Bluetooth\n",
      "  - Directory Services\n",
      "  - Finder\n",
      "  - Foundation\n",
      "  - HelpViewer\n",
      "  - LDAP\n",
      "  - libXpm\n",
      "  - lukemftpd\n",
      "  - NetInfo\n",
      "  - ServerAdmin\n",
      "  - sudo\n",
      "  - Terminal\n",
      "  - VPN\n",
      "\n",
      "These programs have multiple vulnerabilities that could allow a\n",
      "remote attacker to execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://support.apple.com/kb/TA23185"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Install Security Update 2005-005."
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
# MacOS X 10.2.8, 10.3.9 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.[789]\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?2005-005", string:packages)) security_hole(0);
	else non_vuln = 1;
}
else if ( egrep(pattern:"Darwin.* (6\.9|[0-9][0-9]\.|7\.[0-9][0-9]\.)", string:uname) ) non_vuln = 1;

if ( non_vuln )
{
 set_kb_item(name:"CVE-2005-0193", value:TRUE);
}
