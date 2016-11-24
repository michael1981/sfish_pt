#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if (description)
{
  script_id(29699);
  script_version("$Revision: 1.5 $");
  script_cve_id("CVE-2007-4706", "CVE-2007-4707", "CVE-2007-6166");
  script_bugtraq_id(26549, 26866, 26868);
  script_xref(name:"OSVDB", value:"40876");
  script_xref(name:"OSVDB", value:"40883");
  script_xref(name:"OSVDB", value:"40884");

  script_name(english:"QuickTime < 7.3.1 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of QuickTime on Mac OS X");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of QuickTime installed on the remote Mac OS X host is older
than 7.3.1.  Such versions contain several vulnerabilities that may
allow an attacker to execute arbitrary code on the remote host if he
can trick the user to open a specially-crafted RTSP movie, QTL file,
or Flash media file with QuickTime." );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=307176" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2007/Dec/msg00000.html" );
 script_set_attribute(attribute:"solution", value:
"Either use QuickTime's Software Update preference to upgrade to the
latest version or manually upgrade to QuickTime 7.3.1 or later." );
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
     (int(version[0]) == 7 && int(version[1]) < 3 ) ||
     (int(version[0]) == 7 && int(version[1]) == 3 && int(version[2]) < 1) ) 
		security_hole(0);
