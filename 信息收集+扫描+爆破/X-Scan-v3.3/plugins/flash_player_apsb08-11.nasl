#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31799);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2007-0071", "CVE-2007-5275", "CVE-2007-6019", "CVE-2007-6243",
                "CVE-2007-6637", "CVE-2008-1654", "CVE-2008-1655");
  script_bugtraq_id(26930, 26966, 27034, 28694, 28695, 28696, 28697);
  script_xref(name:"OSVDB", value:"41487");
  script_xref(name:"OSVDB", value:"41489");
  script_xref(name:"OSVDB", value:"41490");
  script_xref(name:"OSVDB", value:"43979");
  script_xref(name:"OSVDB", value:"44282");
  script_xref(name:"OSVDB", value:"44279");
  script_xref(name:"OSVDB", value:"44283");
  script_xref(name:"OSVDB", value:"51567");
  script_xref(name:"Secunia", value:"28083");

  script_name(english:"Flash Player Multiple Vulnerabilities (APSB08-11)");
  script_summary(english:"Checks version of Flash Player");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a browser plugin that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the instance of Flash Player on the
remote Windows host is affected by multiple issues, including several
that could allow for arbitrary code execution." );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb08-11.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Flash Player version 9.0.124.0 / 8.0.42.0 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
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
          (iver[0] == 8 && iver[1] == 0 && iver[2] < 42) ||
          (iver[0] == 9 && iver[1] == 0 && iver[2] < 124)
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
    "\n",
    "Nessus has identified the following vulnerable instance(s) of Flash\n",
    "Player installed on the remote host :\n",
    "\n",
    info
  );
  security_hole(port:get_kb_item("SMB/transport"), extra:report);
}
