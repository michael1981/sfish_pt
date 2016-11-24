#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35742);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-0114", "CVE-2009-0519", "CVE-2009-0520", "CVE-2009-0522");
  script_bugtraq_id(33880, 33890);
  script_xref(name:"OSVDB", value:"52745");
  script_xref(name:"OSVDB", value:"52747");
  script_xref(name:"OSVDB", value:"52748");
  script_xref(name:"OSVDB", value:"52749");

  script_name(english:"Flash Player Multiple Vulnerabilities (APSB09-01)");
  script_summary(english:"Checks version of Flash Player");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Windows host contains a browser plugin that is affected by \n",
      "multiple vulnerabilities."
    )
  );

  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote Windows host contains a version of Adobe Flash Player that \n",
      "is earlier than 10.0.22.87 / 9.0.159.0. Such versions are reportedly \n",
      "affected by multiple vulnerabilities : \n",
      "\n",
      "  - A buffer overflow issue that could allow an attacker \n",
      "    to execute arbitrary code with the privileges of the \n",
      "    user running the application. (CVE-2009-0520) \n",
      "\n",
      "  - An input validation vulnerability that leads to a denial \n",
      "    of service attack and could possibly allow for an attacker \n",
      "    to execute arbitrary code. (CVE-2009-0519) \n",
      "\n",
      "  - A vulnerability in the Flash Player settings manager that \n",
      "    could contribute to a clickjacking attack. (CVE-2009-0014) \n",
      "\n",
      "  - A vulnerability with the mouse pointer display that could \n",
      "    contribute to a clickjacking attack. (CVE-2009-0522)"
    )
  );

  script_set_attribute(
    attribute:"see_also",
    value:string(
      "http://labs.idfense.com/intelligence/vulnerabilities/display.php?id=773"
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:string(
      "http://www.adobe.com/support/security/bulletins/apsb09-01.html"
    )
  );

  script_set_attribute(
    attribute:"solution",
    value:string(
      "Upgrade to version 10.0.22.87 or later. If you are unable to \n",
      "upgrade to version 10, upgrade to version 9.0.159.0 or later."
    )
  );

  script_set_attribute(
    attribute:"cvss_vector",
    value:string(
      "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
    )
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_dependencies("flash_player_installed.nasl");
  script_require_keys("SMB/Flash_Player/installed");
  exit(0);
}

#

if (!get_kb_item("SMB/Flash_Player/installed")) exit(0);

include ("global_settings.inc");

# Identify vulnerable versions.
info=NULL;

foreach variant (make_list("Plugin", "ActiveX"))
{
  vers = get_kb_list("SMB/Flash_Player/"+variant+"/Version/*");
  files = get_kb_list("SMB/Flash_Player/"+variant+"/File/*");
  if(!isnull(vers) && !isnull(files))
  {
    foreach key (keys(vers))
    {
      ver = vers[key];


      if (ver)
      {
        iver = split(ver, sep:'.',keep:FALSE);
        for(i=0;i<max_index(iver);i++)
          iver[i] = int(iver[i]);
        if (
          (
            iver[0] == 10 && iver[1] == 0 &&
              (
                iver[2] < 12 ||
                (iver[2] == 12 && iver[3] <= 36)
              )
          ) ||
          (iver[0] == 9 && iver[1] == 0 && iver[2] < 159) ||
          iver[0] < 9
        )
        {
          num = key - ("SMB/Flash_Player/"+variant+"/Version/");
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
  if (report_verbosity > 0)
  {
    # nb: each vulnerable instance adds 2 lines to 'info'.
    if (max_index(split(info)) > 2) s = "s";
    else s = "";

    report = string(
      "\n",
      "Nessus has identified the following vulnerable instance", s, " of Flash\n",
      "Player installed on the remote host :\n",
      "\n",
      info
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
