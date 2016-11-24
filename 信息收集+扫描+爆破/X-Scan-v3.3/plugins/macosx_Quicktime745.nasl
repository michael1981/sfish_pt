#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31736);
  script_version("$Revision: 1.4 $");

  if (NASL_LEVEL >= 3004)
  {
    script_cve_id("CVE-2008-1013", "CVE-2008-1014", "CVE-2008-1015", "CVE-2008-1016", "CVE-2008-1017",
                  "CVE-2008-1018", "CVE-2008-1019", "CVE-2008-1020", "CVE-2008-1021", "CVE-2008-1022",
                  "CVE-2008-1023");
    script_bugtraq_id(28583);
    script_xref(name:"OSVDB", value:"44002");
    script_xref(name:"OSVDB", value:"44003");
    script_xref(name:"OSVDB", value:"44004");
    script_xref(name:"OSVDB", value:"44005");
    script_xref(name:"OSVDB", value:"44006");
    script_xref(name:"OSVDB", value:"44007");
    script_xref(name:"OSVDB", value:"44008");
    script_xref(name:"OSVDB", value:"44009");
    script_xref(name:"OSVDB", value:"44010");
    script_xref(name:"OSVDB", value:"44011");
    script_xref(name:"OSVDB", value:"44012");
    script_xref(name:"Secunia", value:"29650");
  }

  script_name(english:"QuickTime < 7.4.5 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of QuickTime on Mac OS X");

 script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of QuickTime installed on the remote Mac OS X host is
older than 7.4.5.  Such versions contain several vulnerabilities :

  - Untrusted Java applets may obtain elevated privileges
    (CVE-2008-1013).

  - Downloading a movie file may lead to information 
    disclosure (CVE-2008-1014).

  - Viewing a specially-crafted movie file may lead to a
    program crash or arbitrary code execution
    (CVE-2008-1015, CVE-2008-1016, CVE-2008-1017, 
    CVE-2008-1018, CVE-2008-1021, CVE-2008-1022).

  - Opening a specially-crafted PICT image file may lead 
    to a program crash or arbitrary code execution
    (CVE-2008-1019, CVE-2008-1020, CVE-2008-1023)." );
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT1241" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Apr//msg00000.html" );
 script_set_attribute(attribute:"solution", value:
"Either use QuickTime's Software Update preference to upgrade to the
latest version or manually upgrade to QuickTime 7.4.5 or later." );
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
      (iver[1] == 4 && iver[2] < 5)
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
