#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39448);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(35402);
  script_xref(name:"OSVDB", value:"55107");
  script_xref(name:"Secunia", value:"35467");

  script_name(english:"Sophos Anti-Virus For Windows CAB File Scan Evasion Vulnerability");
  script_summary(english:"Checks the virus engine number");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host is running anti-virus software with a file scan\n",
      "evasion vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "According to its engine number, the version of Sophos Anti-Virus\n",
      "running on the remote Windows host has a scan evasion vulnerability.\n",
      "Specially crafted CAB files can exploit this to bypass anti-virus\n",
      "scanning."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.sophos.com/support/knowledgebase/article/59992.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Sophos Anti-Virus engine version 2.87.1 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("sophos_installed.nasl");
  script_require_keys("Antivirus/Sophos/installed", "Antivirus/Sophos/eng_ver");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");

# Get the signature database update for the target.
engine = get_kb_item("Antivirus/Sophos/eng_ver");
if (!engine) exit(1, "Sophos virus engine version wasn't detected");

ver = split(engine, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

fix = split("2.87.1", sep:'.', keep:FALSE);
for (i=0; i<max_index(fix); i++)
  fix[i] = int(fix[i]);

for (i=0; i<max_index(ver); i++)
  if ((ver[i] < fix[i]))
  {
    ver = string(ver[0], ".", ver[1], ".", ver[2]);
    report = string(
      "\n",
      "Virus engine version : ", ver, "\n",
      "Should be            : 2.87.1\n"
    );
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
    exit(0);
    break;
  }
  else if (ver[i] > fix[i])
    break;

exit(1, "The virus engine is not vulnerable");
