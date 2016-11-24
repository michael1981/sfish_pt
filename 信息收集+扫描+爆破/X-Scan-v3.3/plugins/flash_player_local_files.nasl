#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(11952);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2003-1017");
  script_bugtraq_id(8900);
  script_xref(name:"OSVDB", value:"3057");

  script_name(english:"Flash Player < 7.0.19.0 Predictable Data Location Weakness");
  script_summary(english:"Determines the version of the remote flash plugin");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by a remote
file disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Flash Player older than
7.0.19.0. 

Such versions can be abused in conjunction with several flaws in the
web browser to read local files on an affected system. 

To exploit this issue, an attacker would need to lure a user of the
software into visiting a rogue website containing a malicious Flash
applet." );
 script_set_attribute(attribute:"see_also", value:"http://www.macromedia.com/devnet/security/security_zone/mpsb03-08.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 7.0.19.0 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
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
          (iver[0] == 6 && iver[1] == 0 && iver[2] < 88) ||
          (iver[0] == 7 && iver[1] == 0 && iver[2] < 19)
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
