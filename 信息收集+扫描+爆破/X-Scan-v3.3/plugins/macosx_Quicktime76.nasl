#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35436);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-0001", "CVE-2009-0002", "CVE-2009-0003", "CVE-2009-0004",
                "CVE-2009-0005", "CVE-2009-0006", "CVE-2009-0007");
  script_bugtraq_id(33384, 33385, 33386, 33387, 33388, 33389, 33390);
  script_xref(name:"OSVDB", value:"51524");
  script_xref(name:"OSVDB", value:"51525");
  script_xref(name:"OSVDB", value:"51526");
  script_xref(name:"OSVDB", value:"51527");
  script_xref(name:"OSVDB", value:"51528");
  script_xref(name:"OSVDB", value:"51529");
  script_xref(name:"OSVDB", value:"51530");

  script_name(english:"QuickTime < 7.6 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of QuickTime on Mac OS X");

 script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of QuickTime installed on the remote Mac OS X host is
older than 7.6.  Such versions contain several vulnerabilities :

  - A heap buffer overflow in QuickTime's handling of RTSP
    URLs may lead to an application crash or arbitrary code
    execution. (CVE-2009-0001)

  - A heap buffer overflow in QuickTime's handling of THKD
    atoms in QTVR (QuickTime Virtual Reality) movie files
    may lead to an application crash or arbitrary code
    execution. (CVE-2009-0002)

  - A heap buffer overflow while processing an AVI movie
    file may lead to an application crash or arbitrary code
    execution. (CVE-2009-0003)

  - A buffer overflow in the handling of MPEG-2 video files
    with MP3 audio content may lead to an application crash 
    or arbitrary code execution. (CVE-2009-0004)

  - A memory corruption in QuickTime's handling of H.263
    encoded movie files may lead to an application crash or 
    arbitrary code execution. (CVE-2009-0005)

  - A signedness issue in QuickTime's handling of Cinepak
    encoded movie files may result in a heap buffer
    overflow. (CVE-2009-0006)

  - A heap buffer overflow in QuickTime's handling of jpeg 
    atoms in QuickTime movie files may lead to an 
    application crash or arbitrary code execution.
    (CVE-2009-0007)" );
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3403" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2009/Jan/msg00000.html" );
 script_set_attribute(attribute:"solution", value:
"Either use QuickTime's Software Update preference to upgrade to the
latest version or manually upgrade to QuickTime 7.6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
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
  (iver[0] == 7 && iver[1] < 6)
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
