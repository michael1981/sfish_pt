#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20158);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-2628", "CVE-2005-3591");
  script_bugtraq_id(15332, 15334);
  script_xref(name:"OSVDB", value:"18825");
  script_xref(name:"OSVDB", value:"20867");

  script_name(english:"Flash Player < 7.0.60.0 / 8.0.22.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Flash Player");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by remote
code execution flaws." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the instance of Macromedia's Flash
Player on the remote host fails to validate the frame type identifier
from SWF files before using that as an index into an array of function
pointers.  An attacker may be able to leverage this issue using a
specially-crafted SWF file to execute arbitrary code on the remote
host subject to the permissions of the user running Flash Player." );
 script_set_attribute(attribute:"see_also", value:"http://research.eeye.com/html/advisories/published/AD20051104.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.macromedia.com/devnet/security/security_zone/mpsb05-07.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Flash Player version 8.0.22.0 / 7.0.60.0 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("flash_player_installed.nasl");
  script_require_keys("SMB/Flash_Player/installed");
  exit(0);
}

#

if (!get_kb_item("SMB/Flash_Player/installed")) exit(0);

# Identify vulnerable versions.
info = "";

foreach variant (make_list("Plugin", "ActiveX"))
{
  vers = get_kb_list("SMB/Flash_Player/"+variant+"/Version/*");
  files = get_kb_list("SMB/Flash_Player/"+variant+"/File/*");
  if (!isnull(vers) && !isnull(files))
  {
    foreach key (keys(vers))
    {
      num = key - ("SMB/Flash_Player/"+variant+"/Version/");

      ver = vers[key];
      if (ver)
      {
        iver = split(ver, sep:'.', keep:FALSE);
        for (i=0; i<max_index(iver); i++)
          iver[i] = int(iver[i]);

        if (
          iver[0] < 6 ||
          (iver[0] == 7 && iver[1] == 0 && iver[2] <= 53)
        )
        {
          file = files["SMB/Flash_Player/"+variant+"/File/"+num];
          if (variant == "Plugin")
          {
            info += '  - Browser Plugin (for Firefox / Netscape / Opera) :\n';
          }
          else if (variant == "ActiveX")
          {
            info += '  - ActiveX control (for Internet Explorer) :\n';
          }
          info += '    ' + file + ', ' + ver + '\n';
        }
      }
    }
  }
}


if (info)
{
  report = string(
    "Nessus has identified the following vulnerable instance(s) of Flash\n",
    "Player installed on the remote host :\n",
    "\n",
    info
  );
  security_hole(port:get_kb_item("SMB/transport"), extra:report);
}
