#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42290);
  script_version("$Revision: 1.4 $");

  script_bugtraq_id(36848); 
  script_xref(name:"OSVDB", value:"59356");
  script_xref(name:"Secunia", value:"37179");

  script_name(english:"McAfee Anti-Virus TAR/PDF File Scan Evasion");
  script_summary(english:"Checks DAT version");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote anti-virus software is affected by scan evasion\n",
      "vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote host has an anti-virus product from McAfee installed.\n",
      "The DAT file version of the installed anti-virus product is older\n",
      "than 5693, and hence it may be possible for certain TAR or PDF files\n",
      "to evade detection from the scanning engine."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.g-sec.lu/mcafee-pdf-bypass.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.neohapsis.com/archives/bugtraq/2009-10/0274.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10003"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update DAT files to version 5693 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C"
  );

  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/10/28"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/10/20"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/10/28"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_dependencies("mcafee_installed.nasl");
  script_require_keys("Antivirus/McAfee/installed","Antivirus/McAfee/dat_version");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");

dat = get_kb_item("Antivirus/McAfee/dat_version");
if (!dat) exit(1, "The 'Antivirus/McAfee/dat_version' KB item is missing.");

if (date > 0 && dat < 5693)
{
  port = get_kb_item("SMB/transport");

  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "DAT file version ", dat, " is installed on the remote system.\n"
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
