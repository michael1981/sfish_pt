#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35288);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2008-5724");
  script_bugtraq_id(32917);
  script_xref(name:"Secunia", value:"33210");

  script_name(english:"NOD32 3.0/ESET Smart Security < 3.0.684 Local Privilege Escalation");
  script_summary(english:"Checks version of NOD32 3.0/ESET Smart Security"); 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a local
privilege escalation issue." );
 script_set_attribute(attribute:"description", value:
"NOD32 3.0/ESET Smart Security is installed on the remote host.  The
installed version is older than 3.0.684.  Such versions are reportedly
affected by a local privilege escalation issue.  By sending a
specially crafted request to an IOCTL request handler in 'epfw.sys', a
local user may be able to execute arbitrary code with kernel
privileges on the remote system." );
 script_set_attribute(attribute:"see_also", value:"http://www.ntinternals.org/ntiadv0807/ntiadv0807.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76a71440" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to NOD32 3.0/ESET Smart Security v3.0.684 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );
 
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("nod32_installed.nasl");
  script_require_keys("Antivirus/NOD32/version");

  exit(0);
}

include("global_settings.inc");

ver = get_kb_item("Antivirus/NOD32/version");
if (isnull(ver)) exit(0);

v = split(ver, sep:'.', keep:FALSE);
for (i=0; i < max_index(v); i++)
  v[i] = int(v[i]);

if ((v[0] < 3) ||
    (v[0] == 3 && v[1] == 0 && v[2] < 684)
   ) 
{
  # nb: the GUI only reports 3 parts of the version.
  if (report_verbosity)
  {
   version = string(v[0], ".", v[1], ".", v[2]);
   report = string(
     "\n",
     "Version ", version, " of NOD32 3.0/ESET Smart Security is currently installed\n",
     "on the remote host.\n"
   );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else
    security_hole(get_kb_item("SMB/transport"));
}
