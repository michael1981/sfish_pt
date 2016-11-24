#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40434);
  script_version("$Revision: 1.5 $");

  script_cve_id(  'CVE-2009-1862', 'CVE-2009-0901', 'CVE-2009-2493',
                  'CVE-2009-1863', 'CVE-2009-1864', 'CVE-2009-1865', 'CVE-2009-1866',
                  'CVE-2009-1867', 'CVE-2009-1868', 'CVE-2009-1869', 'CVE-2009-1870');
  script_bugtraq_id(35759, 35832, 35846, 35900, 35901, 35902, 35903, 35904,
                    35905, 35906, 35907, 35908);
    # BID 35890,                            it's been retired
  script_xref(name:"OSVDB", value:"56282");
  script_xref(name:"OSVDB", value:"56696");
  script_xref(name:"OSVDB", value:"56698");
  script_xref(name:"OSVDB", value:"56696");
  script_xref(name:"OSVDB", value:"56671");
  script_xref(name:"OSVDB", value:"56672");
  script_xref(name:"OSVDB", value:"56673");
  script_xref(name:"OSVDB", value:"56674");
  script_xref(name:"OSVDB", value:"56675");
  script_xref(name:"OSVDB", value:"56676");
  script_xref(name:"OSVDB", value:"56677");
  script_xref(name:"OSVDB", value:"56678");

  script_name(english:"Flash Player Multiple Vulnerabilities (APSB09-10)");
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
      "is earlier than 10.0.32.18 / 9.0.246.0. Such versions are reportedly \n",
      "affected by multiple vulnerabilities : \n",
      "\n",
      "  - A memory corruption vulnerability that could potentially\n",
      "    lead to code execution. (CVE-2009-1862) \n",
      "\n",
      "  - A vulnerability in the Microsoft Active Template Library\n",
      "    (ATL) which could allow an attacker who successfully\n",
      "    exploits the vulnerability to take control of the\n",
      "    affected system. (CVE-2009-0901, CVE-2009-2395,\n",
      "    CVE-2009-2493) \n",
      "\n",
      "  - A privilege escalation vulnerability that could \n",
      "    potentially lead to code execution. (CVE-2009-1863)\n",
      "\n",
      "  - A heap overflow vulnerability that could potentially\n",
      "    lead to code execution. (CVE-2009-1864) \n",
      "\n",
      "  - A null pointer vulnerability that could potentially\n",
      "    lead to code execution. (CVE-2009-1865) \n",
      "\n",
      "  - A stack overflow vulnerability that could potentially\n",
      "    lead to code execution. (CVE-2009-1866) \n",
      "\n",
      "  - A clickjacking vulnerability that could allow an\n",
      "    attacker to lure a web browser user into unknowingly\n",
      "    clicking on a link or dialog. (CVE-2009-1867 \n",
      "\n",
      "  - A URL parsing heap overflow vulnerability that could\n",
      "    potentially lead to code execution. (CVE-2009-1868)\n",
      "\n",
      "  - An integer overflow vulnerability that could potentially\n",
      "    lead to code execution. (CVE-2009-1869) \n",
      "\n",
      "  - A local sandbox vulnerability that could potentially\n",
      "    lead to information disclosure when SWFs are saved to\n",
      "    the hard drive. CVE-2009-1870) \n"
    )
  );

  script_set_attribute(
    attribute:"see_also",
    value:string(
      "http://www.adobe.com/support/security/bulletins/apsb09-10.html"
    )
  );

  script_set_attribute(
    attribute:"solution",
    value:string(
      "Upgrade to version 10.0.32.18 or later. If you are unable to upgrade\n",
      "to version 10, upgrade to version 9.0.246.0 or later."
    )
  );

  script_set_attribute(
    attribute:"cvss_vector",
    value:string(
      "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
    )
  );

  script_set_attribute( attribute:'vuln_publication_date', value:'2009/07/28' );
  script_set_attribute( attribute:'patch_publication_date', value:'2009/07/30' );
  script_set_attribute( attribute:'plugin_publication_date', value:'2009/07/30' );

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
                iver[2] < 22 ||
                (iver[2] == 22 && iver[3] <= 87)
              )
          ) ||
          (iver[0] == 9 && iver[1] == 0 && iver[2] < 246) ||
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
    if (max_index(split(info)) > 2)
      inst = "s";
    else
      inst = "";

    report = string(
      "\n",
      "Nessus has identified the following vulnerable instance", inst, " of Flash\n",
      "Player installed on the remote host :\n",
      "\n",
      info
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
