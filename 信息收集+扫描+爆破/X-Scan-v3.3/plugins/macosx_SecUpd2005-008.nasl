#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(19773);
 script_version ("$Revision: 1.9 $");

 if (NASL_LEVEL >= 3000)
 {
  script_cve_id("CVE-2005-1992", "CVE-2005-2524", "CVE-2005-2741", "CVE-2005-2742", "CVE-2005-2743",
                "CVE-2005-2744", "CVE-2005-2745", "CVE-2005-2746", "CVE-2005-2747", "CVE-2005-2748");
 }
 script_bugtraq_id(14914, 14939);
 script_xref(name:"OSVDB", value:"17407");
 script_xref(name:"OSVDB", value:"19703");
 script_xref(name:"OSVDB", value:"19704");
 script_xref(name:"OSVDB", value:"19705");
 script_xref(name:"OSVDB", value:"19706");
 script_xref(name:"OSVDB", value:"19707");
 script_xref(name:"OSVDB", value:"19708");
 script_xref(name:"OSVDB", value:"19709");
 script_xref(name:"OSVDB", value:"19710");

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2005-008)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote operating system is missing a vendor supplied patch." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Apple Mac OS X, but lacks 
Security Update 2005-008. 

This security update contains fixes for the following
applications :

- ImageIO
- LibSystem
- Mail
- QuickDraw
- Ruby
- SecurityAgent
- securityd" );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=302413" );
 script_set_attribute(attribute:"solution", value:
"Mac OS X 10.4 :
http://www.apple.com/support/downloads/securityupdate2005008macosx1042.html

Mac OS X 10.3 :
http://www.apple.com/support/downloads/securityupdate2005008macosx1039.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Check for Security Update 2005-008");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);


uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.* (7\.[0-9]\.|8\.2\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?(2005-008|2006-00[123467]|2007-003)", string:packages)) security_hole(0);
}
