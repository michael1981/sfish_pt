#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24268);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2007-0015");
  script_bugtraq_id(21829);
  script_xref(name:"OSVDB", value:"31023");

  script_name(english:"QuickTime RTSP URL Handler Buffer Overflow (Windows)");
  script_summary(english:"Checks version of QuickTime on Windows");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote version of QuickTime is affected by a buffer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"A buffer overflow vulnerability exists in the RTSP URL handler in the
version of QuickTime installed on the remote host.  Using either HTML,
JavaScript or a QTL file as attack vector and an RTSP URL with a long
path component, a remote attacker may be able to leverage this issue
to execute arbitary code on the remote host subject to the user's
privileges." );
 script_set_attribute(attribute:"see_also", value:"http://applefun.blogspot.com/2007/01/moab-01-01-2007-apple-quicktime-rtsp.html" );
 script_set_attribute(attribute:"see_also", value:"http://projects.info-pull.com/moab/MOAB-01-01-2007.html" );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=304989" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/Security-announce/2007/Jan/msg00000.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/442497" );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/blog/7/" );
 script_set_attribute(attribute:"solution", value:
"Apply Apple's Security Update 2007-001, which is available via the
'Apple Software Update' application, installed with the most recent
version of QuickTime or iTunes." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("quicktime_installed.nasl");
  script_require_keys("SMB/QuickTime/Version");

  exit(0);
}


include("global_settings.inc");


ver_ui = get_kb_item("SMB/QuickTime/Version_UI");
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
      iver[1] < 1 ||
      (
        iver[1] == 1 &&
        (
          iver[2] < 3 ||
          (iver[2] == 3 && iver[3] < 191)
        )
      )
    )
  )
)
{
  if (report_verbosity > 0 && ver_ui)
  {
    report = string(
      "\n",
      "QuickTime ", ver_ui, " is currently installed on the remote host.\n"
    );
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
}
