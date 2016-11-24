#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
if ( NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if(description)
{
 script_id(16251);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2005-0125", "CVE-2005-0126", "CVE-2004-0989", "CVE-2005-0127", "CVE-2003-0860", 
               "CVE-2003-0863", "CVE-2004-0594", "CVE-2004-0595", "CVE-2004-1018", "CVE-2004-1019", 
               "CVE-2004-1020", "CVE-2004-1063", "CVE-2004-1064", "CVE-2004-1065", "CVE-2004-1314", 
               "CVE-2004-1036");
 script_bugtraq_id(12367, 12366, 12297, 11857);
 script_xref(name:"OSVDB", value:"7870");
 script_xref(name:"OSVDB", value:"7871");
 script_xref(name:"OSVDB", value:"11179");
 script_xref(name:"OSVDB", value:"11180");
 script_xref(name:"OSVDB", value:"11324");
 script_xref(name:"OSVDB", value:"11603");
 script_xref(name:"OSVDB", value:"11669");
 script_xref(name:"OSVDB", value:"11670");
 script_xref(name:"OSVDB", value:"11671");
 script_xref(name:"OSVDB", value:"12410");
 script_xref(name:"OSVDB", value:"12411");
 script_xref(name:"OSVDB", value:"12412");
 script_xref(name:"OSVDB", value:"12413");
 script_xref(name:"OSVDB", value:"12415");
 script_xref(name:"OSVDB", value:"12600");
 script_xref(name:"OSVDB", value:"12602");
 script_xref(name:"OSVDB", value:"13180");
 script_xref(name:"OSVDB", value:"13181");
 script_xref(name:"OSVDB", value:"13182");
 script_xref(name:"OSVDB", value:"13183");
 script_xref(name:"OSVDB", value:"14932");
 script_xref(name:"OSVDB", value:"34717");

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2005-001)");
 script_summary(english:"Check for Security Update 2005-001");

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
     "The remote host is missing Security Update 2005-001. This security\n",
      "update contains a number of fixes for the following programs :\n",
      "\n",
      "  - at commands\n",
      "  - ColorSync\n",
      "  - libxml2\n",
      "  - Mail\n",
      "  - PHP\n",
      "  - Safari\n",
      "  - SquirrelMail\n",
      "\n",
      "These programs have multiple vulnerabilities which may allow a remote\n",
      "attacker to execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://support.apple.com/kb/TA22859"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Install Security Update 2005-001."
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
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.7\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecUpd(Srvr)?2005-001", string:packages) ) security_hole(0);
	else non_vuln = 1;
}
else if ( egrep(pattern:"Darwin.* (6\.9|[0-9][0-9]\.|7\.([8-9]\.|[0-9][0-9]\.))", string:uname) ) non_vuln = 1;

if ( non_vuln )
{
 list = make_list("CVE-2005-0125", "CVE-2005-0126", "CVE-2004-0989", "CVE-2005-0127", "CVE-2003-0860", "CVE-2003-0863", "CVE-2004-0594", "CVE-2004-0595", "CVE-2004-1018", "CVE-2004-1019", "CVE-2004-1020", "CVE-2004-1063", "CVE-2004-1064", "CVE-2004-1065", "CVE-2004-1314", "CVE-2004-1036");
 foreach cve (list) set_kb_item(name:cve, value:TRUE);
}
