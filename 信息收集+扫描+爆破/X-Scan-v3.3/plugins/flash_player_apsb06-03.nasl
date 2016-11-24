#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21079);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2006-0024");
  script_bugtraq_id(17106);
  script_xref(name:"OSVDB", value:"23908");

  script_name(english:"Flash Player swf Processing Multiple Unspecified Code Execution (APSB06-03)");
  script_summary(english:"Checks version of Flash Player");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a browser plugin that is affected by
several critical flaws." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the instance of Flash Player on the
remote Windows host contains multiple critical and as-yet unspecified
vulnerabilities that could allow an attacker to take control of the
affected host.  To exploit these issues, a user must load a malicious
SWF file in Flash Player." );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/technet/security/Bulletin/MS06-020.mspx" );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/technet/security/advisory/916208.mspx" );
 script_set_attribute(attribute:"see_also", value:"http://www.macromedia.com/devnet/security/security_zone/apsb06-03.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Flash Player version 8.0.24.0 / 7.0.63.0 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );


script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
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
          (iver[0] == 6 && iver[1] == 0 && iver[2] < 84) ||
          (iver[0] == 7 && iver[1] == 0 && iver[2] < 63) ||
          (iver[0] == 8 && iver[1] == 0 && iver[2] < 24)
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
  security_warning(port:get_kb_item("SMB/transport"), extra:report);
}
