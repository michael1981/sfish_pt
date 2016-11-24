#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40663);
  script_version("$Revision: 1.1 $");

  script_cve_id("CVE-2009-2694");
  script_bugtraq_id(36071);
  script_xref(name:"Secunia", value:"36384");

  script_name(english:"Pidgin < 2.5.9 'msn_slplink_process_msg()' Memory Corruption");
  script_summary(english:"Does a version check");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host has an instant messaging client that is affected by a\n",
      "memory corruption vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of Pidgin installed on the remote host is earlier than\n",
      "2.5.9.  Such versions are reportedly affected by a vulnerability in\n",
      "'msn_slplink_process_msg()'.  Maliciously crafted MSN SLP messages\n",
      "can result in memory corruption.  A remote attacker could use this to\n",
      "crash the client, or execute arbitrary code.\n",
      "\n",
      "This attack does not require user interaction or that the attacker\n",
      "is in the victim's buddy list (using the default configuration).\n"
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.coresecurity.com/content/libpurple-arbitrary-write"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.neohapsis.com/archives/bugtraq/2009-08/0158.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://pidgin.im/news/security/?id=34"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Pidgin 2.5.9 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/08/18"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/08/18"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/08/20"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("pidgin_installed.nasl");
  script_require_keys("SMB/Pidgin/Version");

  exit(0);
}


include("global_settings.inc");


version = get_kb_item("SMB/Pidgin/Version");
if (isnull(version)) exit(1, "The 'SMB/Pidgin/Version' KB item is missing.");

ver_fields = split(version, sep:'.', keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);
rev = int(ver_fields[2]);

# Versions < 2.5.9 are affected
if (
  major < 2 ||
  (major == 2 && minor < 5) ||
  (major == 2 && minor == 5 && rev < 9)
)
{
  port = get_kb_item("SMB/transport");

  if(report_verbosity > 0)
  {
    report = string(
      "\n",
      "  Installed version  : ", version, "\n",
      "  Should be at least : 2.5.9\n"
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "Version " + version + " is not affected.");

