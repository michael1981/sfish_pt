#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34741);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2007-4324", "CVE-2007-6243", "CVE-2008-3873", "CVE-2008-4401", "CVE-2008-4503",
                "CVE-2008-4818", "CVE-2008-4819", "CVE-2008-4820", "CVE-2008-4821", "CVE-2008-4822", 
                "CVE-2008-4823", "CVE-2008-4824");
  script_bugtraq_id(25260, 26966, 31117, 32129);
  script_xref(name:"OSVDB", value:"41475");
  script_xref(name:"OSVDB", value:"41487");
  script_xref(name:"OSVDB", value:"48049");
  script_xref(name:"OSVDB", value:"48944");
  script_xref(name:"OSVDB", value:"49753");
  script_xref(name:"OSVDB", value:"49780");
  script_xref(name:"OSVDB", value:"49781");
  script_xref(name:"OSVDB", value:"49783");
  script_xref(name:"OSVDB", value:"49785");
  script_xref(name:"OSVDB", value:"49790");
  script_xref(name:"OSVDB", value:"49958");
  script_xref(name:"OSVDB", value:"50126");
  script_xref(name:"OSVDB", value:"50127");
  script_xref(name:"OSVDB", value:"51567");

  script_name(english:"Flash Player Multiple Vulnerabilities (APSB08-18 / APSB08-20 / APSB08-22)");
  script_summary(english:"Checks version of Flash Player");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a browser plugin that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"According to its version number, an instance of Flash Player on the
remote Windows host is 9.0.124.0 or earlier.  Such versions are
potentially affected by several vulnerabilities :

  - A potential port-scanning issue. (CVE-2007-4324)

  - Possible privilege escalation attacks against web 
    servers hosting Flash content and cross-domain policy 
    files.  (CVE-2007-6243)

  - Potential Clipboard attacks. (CVE-2008-3873)

  - FileReference upload and download APIs that don't
    require user interaction. (CVE-2008-4401)

  - A 'Clickjacking' issue that could be abused by an 
    attacker to lure a web browser user into unknowingly 
    clicking on a link or dialog. (CVE-2008-4503)

  - A potential cross-site scripting vulnerability. 
    (CVE-2008-4818)

  - A potential issue that could be leveraged in to conduct
    a DNS rebinding attack. (CVE-2008-4819)

  - An information disclosure issue affecting only the 
    ActiveX control. (CVE-2008-4820)

  - An information disclosure issue involving interpretation
    of the 'jar:' protocol and affecting only the plugin for 
    Mozilla browsers. (CVE-2008-4821)

  - An issue with policy file interpretation could 
    potentially lead to bypass of a non-root domain policy. 
    (CVE-2008-4822)

  - A potential HTML injection issue involving an 
    ActionScript attribute. (CVE-2008-4823)

  - Multiple input validation errors could potentially lead
    to execution of arbitrary code. (CVE-2008-4824)" );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/advisories/apsa08-08.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb08-18.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb08-20.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb08-22.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Flash Player version 10.0.12.36 / 9.0.151.0 or later." );
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


include("global_settings.inc");


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
      ver = vers[key];
      if (ver)
      {
        iver = split(ver, sep:'.', keep:FALSE);
        for (i=0; i<max_index(iver); i++)
          iver[i] = int(iver[i]);

        if (
          iver[0] < 9 ||
          (iver[0] == 9 && iver[1] == 0 && iver[2] <= 124)
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
  if (report_verbosity)
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
