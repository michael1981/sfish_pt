#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
  script_id(11323);
  script_version("$Revision: 1.24 $");

  script_bugtraq_id(7005);
  script_xref(name:"OSVDB", value:"58970");

  script_name(english:"Flash Player < 6.0.79.0 Multiple Unspecified Overflows");
  script_summary(english:"Checks version of Flash Player");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin that is prone to buffer
overflow attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host has an old version of the Flash Player plugin
installed. 

An attacker may use this flaw to construct a malicious web site with a
badly-formed Flash animation which, when viewed using a vulnerable
version of the software, will cause a buffer overflow and allow for
arbitrary code execution subject to the plugin user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/devnet/security/security_zone/mpsb03-03.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 6.0.79.0 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

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
          (iver[0] == 6 && iver[1] == 0 && iver[2] < 79)
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
