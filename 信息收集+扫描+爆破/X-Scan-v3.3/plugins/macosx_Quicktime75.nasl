#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(33131);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-1582", "CVE-2008-1583", "CVE-2008-1584", "CVE-2008-1585");
  script_bugtraq_id(29619, 29648, 29650, 29652, 29654);
  script_xref(name:"OSVDB", value:"46070");
  script_xref(name:"OSVDB", value:"46071");
  script_xref(name:"OSVDB", value:"46072");
  script_xref(name:"OSVDB", value:"46073");
  script_xref(name:"Secunia", value:"29293");

  script_name(english:"QuickTime < 7.5 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of QuickTime on Mac OS X");

 script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of QuickTime installed on the remote Mac OS X host is
older than 7.5.  Such versions contain several vulnerabilities :

  - There is a heap buffer overflow in QuickTime's
    handling of PICT image files that could result in a
    program crash or arbitrary code execution
    (CVE-2008-1583).

  - There is a memory corruption issue in QuickTime's
    handling of AAC-encoded media content that could
    result in a program crash or arbitrary code execution
    (CVE-2008-1582).

  - There is a stack buffer overflow in QuickTime's 
    handling of Indeo video codec content that could 
    result in a program crash or arbitrary code execution
    (CVE-2008-1584).

  - There is a URL handling issue in QuickTime's handling
    of 'file:' URLs that may allow launching of arbitrary
    applications (CVE-2008-1585)." );
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT1991" );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-037" );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-038" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/493247/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/493248/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Jun/msg00000.html" );
 script_set_attribute(attribute:"solution", value:
"Either use QuickTime's Software Update preference to upgrade to the
latest version or manually upgrade to QuickTime 7.5 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("macosx_Quicktime652.nasl");
  script_require_keys("MacOSX/QuickTime/Version");
  exit(0);
}

#

include("global_settings.inc");

ver = get_kb_item("MacOSX/QuickTime/Version");
if (isnull(ver)) exit(0);

iver = split(ver, sep:'.', keep:FALSE);
for (i=0; i<max_index(iver); i++)
  iver[i] = int(iver[i]);

if (
  iver[0] < 7 || 
  (iver[0] == 7 && iver[1] < 5)
)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "QuickTime ", ver, " is currently installed on the remote host.\n"
    );
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
