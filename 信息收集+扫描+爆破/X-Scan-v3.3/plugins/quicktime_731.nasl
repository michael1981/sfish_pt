#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(29698);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2007-4706", "CVE-2007-4707", "CVE-2007-6166");
  script_bugtraq_id(26549, 26866, 26868);
  script_xref(name:"OSVDB", value:"40876");
  script_xref(name:"OSVDB", value:"40883");
  script_xref(name:"OSVDB", value:"40884");

  script_name(english:"QuickTime < 7.3.1 Multiple Vulnerabilities (Windows)");
  script_summary(english:"Checks version of QuickTime on Windows");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of QuickTime installed on the remote Windows host is older
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
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("quicktime_installed.nasl");
  script_require_keys("SMB/QuickTime/Version");
  exit(0);
}

#

ver = get_kb_item("SMB/QuickTime/Version");
if (isnull(ver)) exit(0);

iver = split(ver, sep:'.', keep:FALSE);
for (i=0; i<max_index(iver); i++)
  iver[i] = int(iver[i]);

if (
  iver[0] < 7 || 
  (
    iver[0] == 7 && 
    (
      iver[1] < 3 ||
      (iver[1] == 3  && iver[2] < 1)
    )
  )
)
{
  report = string(
    "Version ", ver, " of QuickTime is currently installed\n",
    "on the remote host.\n"
  );
  security_hole(port:get_kb_item("SMB/transport"), extra:report);
}
