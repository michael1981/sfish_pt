#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25694);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2007-3456", "CVE-2007-3457");
  script_bugtraq_id(24856);
  script_xref(name:"OSVDB", value:"38049");
  script_xref(name:"OSVDB", value:"38054");

  script_name(english:"Flash Player Multiple Vulnerabilities (APSB07-12)");
  script_summary(english:"Checks version of Flash Player");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a browser plugin that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the instance of Flash Player on the
remote Windows host could allow for arbitrary code execution by means
of a malicious SWF file. 

In addition, it may also fail to sufficiently validate the HTTP
Referer header, which may aid in cross-site request forgery attacks. 
This issue does not, though, affect Flash Player 9." );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb07-12.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Flash Player version 9.0.47.0 / 8.0.35.0 / 7.0.70.0 or
later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
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
          (iver[0] == 7 && iver[1] == 0 && iver[2] < 70) ||
          (iver[0] == 8 && iver[1] == 0 && iver[2] < 35) ||
          (iver[0] == 9 && iver[1] == 0 && iver[2] < 47)
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
