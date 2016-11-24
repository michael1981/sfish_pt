#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(23869);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2006-5330");
  script_bugtraq_id(20592, 20593);
  script_xref(name:"OSVDB", value:"29863");

  script_name(english:"Flash Player HTTP Header CRLF Injection (APSB06-18)");
  script_summary(english:"Checks version of Flash Player");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a browser plugin that is affected by
multiple HTTP header injection issues." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the instance of Flash Player on the
remote Windows host contains two ways for a remote attacker to perform
arbitrary HTTP requests while controlling most of the HTTP headers.  A
remote attacker may be able to leverage these issues to conduct
cross-site request forgery attacks against a user who visits a
malicious web site." );
 script_set_attribute(attribute:"see_also", value:"http://www.rapid7.com/advisories/R7-0026.jsp" );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb06-18.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Flash Player version 9.0.28.0 / 8.0.34.0 / 7.0.67.0 or
later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );
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
          (iver[0] == 7 && iver[1] == 0 && iver[2] < 67) ||
          (iver[0] == 8 && iver[1] == 0 && iver[2] < 34) ||
          (iver[0] == 9 && iver[1] == 0 && iver[2] < 28)
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
