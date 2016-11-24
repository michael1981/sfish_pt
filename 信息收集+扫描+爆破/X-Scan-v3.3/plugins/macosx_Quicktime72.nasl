#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if (description)
{
  script_id(25704);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2007-2295", "CVE-2007-2296", "CVE-2007-2388", "CVE-2007-2389", "CVE-2007-2392",
                "CVE-2007-2393", "CVE-2007-2394", "CVE-2007-2396", "CVE-2007-2397", "CVE-2007-2402");
  script_bugtraq_id(23650, 23652, 24221, 24222, 24873);
  script_xref(name:"OSVDB", value:"35575");
  script_xref(name:"OSVDB", value:"35576");
  script_xref(name:"OSVDB", value:"35577");
  script_xref(name:"OSVDB", value:"35578");
  script_xref(name:"OSVDB", value:"36131");
  script_xref(name:"OSVDB", value:"36132");
  script_xref(name:"OSVDB", value:"36133");
  script_xref(name:"OSVDB", value:"36134");
  script_xref(name:"OSVDB", value:"36135");
  script_xref(name:"OSVDB", value:"36136");

  script_name(english:"QuickTime < 7.2 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of QuickTime on Mac OS X");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an application that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The version of QuickTime installed on the remote Mac OS X host is older
than 7.2.  Such versions contain several vulnerabilities that may
allow an attacker to execute arbitrary code on the remote host if he
can trick the user to open a specially-crafted file with QuickTime." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-07/0243.html" );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=305947" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2007/Jul/msg00001.html" );
 script_set_attribute(attribute:"solution", value:
"Either use QuickTime's Software Update preference to upgrade to the
latest version or manually upgrade to QuickTime 7.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
 script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("macosx_Quicktime652.nasl");
  script_require_keys("MacOSX/QuickTime/Version");
  exit(0);
}

#

ver = get_kb_item("MacOSX/QuickTime/Version");
if (! ver ) exit(0);

version = split(ver, sep:'.', keep:FALSE);
if ( (int(version[0]) < 7) ||
     (int(version[0]) == 7 && int(version[1]) < 2 ) ) security_hole(0);
