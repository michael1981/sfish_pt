#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(15898);
 script_version ("$Revision: 1.14 $");

 if (NASL_LEVEL >= 3004)
 {
 script_cve_id("CVE-2004-1082", "CVE-2003-0020", "CVE-2003-0987", "CVE-2004-0174", "CVE-2004-0488", 
               "CVE-2004-0492", "CVE-2004-0885", "CVE-2004-0940", "CVE-2004-1083", "CVE-2004-1084", 
               "CVE-2004-0747", "CVE-2004-0786", "CVE-2004-0751", "CVE-2004-0748", "CVE-2004-1081", 
               "CVE-2004-0803", "CVE-2004-0804", "CVE-2004-0886", "CVE-2004-1089", "CVE-2004-1085", 
               "CVE-2004-0642", "CVE-2004-0643", "CVE-2004-0644", "CVE-2004-0772", "CVE-2004-1088", 
               "CVE-2004-1086", "CVE-2004-1123", "CVE-2004-1121", "CVE-2004-1122", "CVE-2004-1087");
 }
 script_bugtraq_id(9921, 9930, 9571, 11471, 11360, 11469, 10508, 11802);
 script_xref(name:"IAVA", value:"2004-t-0027");
 if (NASL_LEVEL >= 3004)
 {
 script_xref(name:"OSVDB", value:"3819");
 script_xref(name:"OSVDB", value:"4382");
 script_xref(name:"OSVDB", value:"4383");
 script_xref(name:"OSVDB", value:"6472");
 script_xref(name:"OSVDB", value:"6839");
 script_xref(name:"OSVDB", value:"9406");
 script_xref(name:"OSVDB", value:"9407");
 script_xref(name:"OSVDB", value:"9408");
 script_xref(name:"OSVDB", value:"9409");
 script_xref(name:"OSVDB", value:"9523");
 script_xref(name:"OSVDB", value:"9742");
 script_xref(name:"OSVDB", value:"9991");
 script_xref(name:"OSVDB", value:"9994");
 script_xref(name:"OSVDB", value:"10637");
 script_xref(name:"OSVDB", value:"10750");
 script_xref(name:"OSVDB", value:"10751");
 script_xref(name:"OSVDB", value:"10909");
 script_xref(name:"OSVDB", value:"11003");
 script_xref(name:"OSVDB", value:"12176");
 script_xref(name:"OSVDB", value:"12192");
 script_xref(name:"OSVDB", value:"12193");
 script_xref(name:"OSVDB", value:"12194");
 script_xref(name:"OSVDB", value:"12198");
 script_xref(name:"OSVDB", value:"12199");
 script_xref(name:"OSVDB", value:"12200");
 script_xref(name:"OSVDB", value:"12201");
 script_xref(name:"OSVDB", value:"12202");
 script_xref(name:"OSVDB", value:"12203");
 script_xref(name:"OSVDB", value:"12206");
 script_xref(name:"OSVDB", value:"12207");
 script_xref(name:"OSVDB", value:"12881");
 }

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2004-12-02)");
 script_summary(english:"Check for Security Update 2004-12-02");
 
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
      "The remote host is missing Security Update 2004-12-02. This security\n",
      "update contains a number of fixes for the following programs :\n",
      "\n",
      "  - Apache\n",
      "  - Apache2\n",
      "  - AppKit\n",
      "  - Cyrus IMAP\n",
      "  - HIToolbox\n",
      "  - Kerberos\n",
      "  - Postfix\n",
      "  - PSNormalizer\n",
      "  - QuickTime Streaming Server\n",
      "  - Safari\n",
      "  - Terminal\n",
      "\n",
      "These programs contain multiple vulnerabilities which may allow a\n",
      "remote attacker to execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://support.apple.com/kb/HT1646"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Install Security Update 2004-12-02."
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
# MacOS X 10.2.8, 10.3.6 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.6\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecUpd(Srvr)?2004-12-02", string:packages) ) security_hole(0);
	else non_vuln = 1;
}
else if ( egrep(pattern:"Darwin.* (6\.9|[0-9][0-9]\.|7\.([7-9]|[0-9][0-9]\.|[8-9]\.))", string:uname) ) non_vuln = 1;

if ( non_vuln )
{
   set_kb_item(name:"CVE-2004-1082", value:TRUE);
   set_kb_item(name:"CVE-2003-0020", value:TRUE);
   set_kb_item(name:"CVE-2003-0987", value:TRUE);
   set_kb_item(name:"CVE-2004-0174", value:TRUE);
   set_kb_item(name:"CVE-2004-0488", value:TRUE);
   set_kb_item(name:"CVE-2004-0492", value:TRUE);
   set_kb_item(name:"CVE-2004-0885", value:TRUE);
   set_kb_item(name:"CVE-2004-0940", value:TRUE);
   set_kb_item(name:"CVE-2004-1083", value:TRUE);
   set_kb_item(name:"CVE-2004-1084", value:TRUE);
   set_kb_item(name:"CVE-2004-0747", value:TRUE);
   set_kb_item(name:"CVE-2004-0786", value:TRUE);
   set_kb_item(name:"CVE-2004-0751", value:TRUE);
   set_kb_item(name:"CVE-2004-0748", value:TRUE);
   set_kb_item(name:"CVE-2004-1081", value:TRUE);
   set_kb_item(name:"CVE-2004-0803", value:TRUE);
   set_kb_item(name:"CVE-2004-0804", value:TRUE);
   set_kb_item(name:"CVE-2004-0886", value:TRUE);
   set_kb_item(name:"CVE-2004-1089", value:TRUE);
   set_kb_item(name:"CVE-2004-1085", value:TRUE);
   set_kb_item(name:"CVE-2004-0642", value:TRUE);
   set_kb_item(name:"CVE-2004-0643", value:TRUE);
   set_kb_item(name:"CVE-2004-0644", value:TRUE);
   set_kb_item(name:"CVE-2004-0772", value:TRUE);
   set_kb_item(name:"CVE-2004-1088", value:TRUE);
   set_kb_item(name:"CVE-2004-1086", value:TRUE);
   set_kb_item(name:"CVE-2004-1123", value:TRUE);
   set_kb_item(name:"CVE-2004-1121", value:TRUE);
   set_kb_item(name:"CVE-2004-1122", value:TRUE);
   set_kb_item(name:"CVE-2004-1087", value:TRUE);
}
