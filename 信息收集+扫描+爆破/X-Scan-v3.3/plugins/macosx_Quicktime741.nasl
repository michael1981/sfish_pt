#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);



include("compat.inc");

if (description)
{
  script_id(30203);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-0234");
  script_bugtraq_id(27225);
  script_xref(name:"OSVDB", value:"40382");

  script_name(english:"QuickTime < 7.4.1 RTSP Response Long Reason-Phrase Arbitrary Remote Code Execution (Mac OS X)");
  script_summary(english:"Checks version of QuickTime on Mac OS X");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an application that is affected by a
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of QuickTime installed on the remote Mac OS X host is
older than 7.4.1.  Such versions contain a heap buffer overflow in the
application's handling of HTTP responses when RTSP tunneling is
enabled.  If an attacker can trick a user to visit a specially-crafted
webpage, he may be able to to execute arbitrary code on the remote
host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/486091" );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=307407" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Feb/msg00001.html" );
 script_set_attribute(attribute:"solution", value:
"Either use QuickTime's Software Update preference to upgrade to the
latest version or manually upgrade to QuickTime 7.4.1 or later." );
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
  (
    iver[0] == 7 && 
    (
      iver[1] < 4 ||
      (iver[1] == 4 && iver[2] < 1)
    )
  )
)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Version ", ver, " of QuickTime is currently installed\n",
      "on the remote host.\n"
    );
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
