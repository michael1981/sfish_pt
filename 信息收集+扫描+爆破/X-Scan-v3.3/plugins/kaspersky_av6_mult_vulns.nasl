#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25021);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2007-0445", "CVE-2007-1112", "CVE-2007-1879", "CVE-2007-1880", "CVE-2007-1881");
  script_bugtraq_id(23325, 23326, 23345, 23346);
  script_xref(name:"OSVDB", value:"33848");
  script_xref(name:"OSVDB", value:"33849");
  script_xref(name:"OSVDB", value:"33850");
  script_xref(name:"OSVDB", value:"33851");
  script_xref(name:"OSVDB", value:"33852");
  script_xref(name:"OSVDB", value:"34328");

  script_name(english:"Kaspersky Anti-Virus < 6.0.2.614 Multiple Vulnerabilities");
  script_summary(english:"Checks product version");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is prone to
various issues." );
 script_set_attribute(attribute:"description", value:
"The version of the Kaspersky anti-virus product installed on the remote
host may be affected by buffer overflow, privilege escalation, and
information disclosure vulnerabilities, depending on the actual
product installed." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=504" );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=505" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2007-04/0105.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2007-04/0106.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-07-013.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-07-014.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.kaspersky.com/technews?id=203038693" );
 script_set_attribute(attribute:"see_also", value:"http://www.kaspersky.com/technews?id=203038694" );
 script_set_attribute(attribute:"solution", value:
"If using Kaspersky Anti-Virus / Kaspersky Internet Security, upgrade
to build 6.0.2.614 or later

If using Kaspersky Anti-Virus for Windows File Servers / Kaspersky
Anti-Virus for Windows Workstation, upgrade to version 6.0 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("kaspersky_installed.nasl");
  script_require_keys("Antivirus/Kaspersky/installed");

  exit(0);
}


# Check for issues from tech news id# 203038693.
prods = make_list(
  "Kaspersky Anti-Virus for Windows File Servers",
  "Kaspersky Anti-Virus for Windows Workstations" 
);
foreach prod (prods)
{
  install = get_kb_item("Antivirus/Kaspersky/" + prod);
  if (!isnull(install))
  {
    matches = eregmatch(pattern:"^([0-9.]+) in (.*)$", string:install);
    if (!isnull(matches))
    {
      ver = matches[1];
      iver = split(ver, sep:'.', keep:FALSE);
      for (i=0; i<max_index(iver); i++)
        iver[i] = int(iver[i]);

      # nb: versions below 6.0 are affected.
      if (iver[0] < 6)
      {
        report = string(
          "\n",
          "  Product : ", prod, "\n",
          "  Version : ", ver, "\n"
        );
        security_hole(port:get_kb_item("SMB/transport"), extra:report);
        exit(0);
      }
    }
  }
}


# Check for issues from tech news id# 203038694.
prods = make_list(
  "Kaspersky Anti-Virus", 
  "Kaspersky Internet Security"
);
foreach prod (prods)
{
  install = get_kb_item("Antivirus/Kaspersky/" + prod);
  if (!isnull(install))
  {
    matches = eregmatch(pattern:"^([0-9.]+) in (.*)$", string:install);
    if (!isnull(matches))
    {
      ver = matches[1];
      iver = split(ver, sep:'.', keep:FALSE);
      for (i=0; i<max_index(iver); i++)
        iver[i] = int(iver[i]);

      # nb: versions 6.0 below 6.0.2.614 are affected.
      if (
        iver[0] == 6 && iver[1] == 0 && 
        (
          iver[2] < 2 ||
          (iver[2] == 2 && iver[3] < 614)
        )
      )
      {
        report = string(
          "\n",
          "  Product : ", prod, "\n",
          "  Version : ", ver, "\n"
        );
        security_hole(port:get_kb_item("SMB/transport"), extra:report);
        exit(0);
      }
    }
  }
}
