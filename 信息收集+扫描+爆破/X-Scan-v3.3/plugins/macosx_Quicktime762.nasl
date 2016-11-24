#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38989);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-0185", "CVE-2009-0188", "CVE-2009-0951", "CVE-2009-0952", "CVE-2009-0953",
                "CVE-2009-0955", "CVE-2009-0956", "CVE-2009-0957");
  script_bugtraq_id(35159, 35161, 35162, 35163, 35164, 35165, 35166, 35167, 35168);
  script_xref(name:"OSVDB", value:"54873");
  script_xref(name:"OSVDB", value:"54874");
  script_xref(name:"OSVDB", value:"54876");
  script_xref(name:"OSVDB", value:"54877");
  script_xref(name:"OSVDB", value:"54878");
  script_xref(name:"OSVDB", value:"54879");
  script_xref(name:"OSVDB", value:"55033");
  script_xref(name:"OSVDB", value:"55071");

  script_name(english:"QuickTime < 7.6.2 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of QuickTime on Mac OS X");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Mac OS X host contains an application that is affected by\n",
      "multiple vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of QuickTime installed on the remote Mac OS X host is\n",
      "older than 7.6.2.  Such versions contain several vulnerabilities :\n",
      "\n",
      "  - A heap buffer overflow in QuickTime's handling of MS \n",
      "    ADPCM encoded audio data may lead to an application \n",
      "    crash or arbitrary code execution. (CVE-2009-0185)\n",
      "\n",
      "  - A memory corruption issue in QuickTime's handling of\n",
      "    Sorenson 3 video files may lead to an application crash\n",
      "    or arbitrary code execution. (CVE-2009-0188)\n",
      "\n",
      "  - A heap buffer overflow in QuickTime's handling of FLC\n",
      "    compression files may lead to an application crash or \n",
      "    arbitrary code execution. (CVE-2009-0951)\n",
      "\n",
      "  - A buffer overflow in QuickTime's handling of compressed\n",
      "    PSD image files may lead to an application crash or \n",
      "    arbitrary code execution. (CVE-2009-0952)\n",
      "\n",
      "  - A heap buffer overflow in QuickTime's handling of PICT\n",
      "    image files may lead to an application crash or \n",
      "    arbitrary code execution. (CVE-2009-0953)\n",
      "\n",
      "  - A sign extension issue in QuickTime's handling of image\n",
      "    description atoms in an Apple video file may lead to an\n",
      "    application crash or arbitrary code execution. \n",
      "    (CVE-2009-0955)\n",
      "\n",
      "  - An uninitialized memory access issue in QuickTime's \n",
      "    handling of movie files may lead to an application \n",
      "    crash or arbitrary code execution. (CVE-2009-0956)\n",
      "\n",
      "  - A heap buffer overflow in QuickTime's handling of JP2\n",
      "    image files may lead to an application crash or \n",
      "    arbitrary code execution. (CVE-2009-0957)"
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT3591"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/jun/msg00000.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to QuickTime 7.6.2 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
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


version = get_kb_item("MacOSX/QuickTime/Version");
if (isnull(version)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 7 || 
  (
    ver[0] == 7 && 
    (
      ver[1] < 6 ||
      (ver[1] == 6 && ver[2] < 2)
    )
  )
)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "QuickTime ", version, " is currently installed on the remote host.\n"
    );
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
