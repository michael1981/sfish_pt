#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if (description)
{
  script_id(21554);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2006-1249", "CVE-2006-1453", "CVE-2006-1454", "CVE-2006-1458", "CVE-2006-1459",
                "CVE-2006-1460", "CVE-2006-1461", "CVE-2006-1462", "CVE-2006-1463", "CVE-2006-1464",
                "CVE-2006-1465", "CVE-2006-2238");
  script_bugtraq_id(17074, 17953);
  script_xref(name:"OSVDB", value:"25508");
  script_xref(name:"OSVDB", value:"25509");
  script_xref(name:"OSVDB", value:"25510");
  script_xref(name:"OSVDB", value:"25511");
  script_xref(name:"OSVDB", value:"25512");
  script_xref(name:"OSVDB", value:"25513");
  script_xref(name:"OSVDB", value:"25514");
  script_xref(name:"OSVDB", value:"25515");
  script_xref(name:"OSVDB", value:"25516");
  script_xref(name:"OSVDB", value:"25517");

  script_name(english:"Quicktime < 7.1 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of Quicktime on Mac OS X");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote version of QuickTime is affected by multiple overflow
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Quicktime prior to
7.1. 

The remote version of Quicktime is vulnerable to various integer and
buffer overflows involving specially-crafted image and media files. 
An attacker may be able to leverage these issues to execute arbitrary
code on the remote host by sending a malformed file to a victim and
having him open it using QuickTime player." );
 script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2006-May/045979.html" );
 script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2006-May/045981.html" );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=303752" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Quicktime version 7.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("macosx_Quicktime652.nasl");
 script_require_keys("MacOSX/QuickTime/Version");
 exit(0);
}

#

ver = get_kb_item("MacOSX/QuickTime/Version");
if ( ! ver ) exit(0);

version = split(ver, sep:'.', keep:FALSE);

if ( int(version[0]) == 7 &&  int(version[1]) == 0 )
		security_hole( 0 );
