#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25703);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2007-2295", "CVE-2007-2296", "CVE-2007-2388", "CVE-2007-2389",
                "CVE-2007-2393", "CVE-2007-2396", "CVE-2007-2397", "CVE-2007-2402"
  );
  script_bugtraq_id(23650, 23652, 24221, 24222, 24873);
  script_xref(name:"OSVDB", value:"35575");
  script_xref(name:"OSVDB", value:"35576");
  script_xref(name:"OSVDB", value:"35577");
  script_xref(name:"OSVDB", value:"35578");
  script_xref(name:"OSVDB", value:"36131");
  script_xref(name:"OSVDB", value:"36132");
  script_xref(name:"OSVDB", value:"36133");
  script_xref(name:"OSVDB", value:"36135");

  script_name(english:"QuickTime < 7.2 Multiple Vulnerabilities (Windows)");
  script_summary(english:"Checks version of QuickTime on Windows");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The version of QuickTime installed on the remote Windows host is older
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

if (iver[0] < 7 || (iver[0] == 7 && iver[1] < 2)) 
{
  report = string(
    "Version ", ver, " of QuickTime is currently installed\n",
    "on the remote host.\n"
  );
  security_hole(port:get_kb_item("SMB/transport"), extra:report);
}
