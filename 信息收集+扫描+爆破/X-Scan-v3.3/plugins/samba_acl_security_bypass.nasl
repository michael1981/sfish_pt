#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39502);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-1886", "CVE-2009-1888");
  script_bugtraq_id(35472);
  script_xref(name:"Secunia", value:"35539");
  script_xref(name:"OSVDB", value:"55411");
  script_xref(name:"OSVDB", value:"55412");

  script_name(english:"Samba < 3.0.35 / 3.2.13 / 3.3.6 Multiple Vulnerabilities");
  script_summary(english:"Checks the remote Samba version");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Samba server may be affected by a security bypass\n",
      "vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "According to its version number, the version of Samba running on the\n",
      "remote host has a security bypass vulnerability.  Access restrictions\n",
      "can be bypassed due to a read of uninitialized data in smbd.  This\n",
      "could allow a user to modify an access control list (ACL), even when\n",
      "they should be denied permission.\n\n",
      "Note the 'dos filemode' parameter must be set to 'yes' in smb.conf\n",
      "in order for an attack to be successful (the default setting is 'no').",
      "\n\nAlso note versions 3.2.0 - 3.2.12 of smbclient are affected by a\n",
      "format string vulnerability, though Nessus has not checked for this."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://us1.samba.org/samba/security/CVE-2009-1888.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://us1.samba.org/samba/security/CVE-2009-1886.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "Upgrade to Samba version 3.3.6 / 3.2.13 / 3.0.35 or later, or apply\n",
      "the appropriate patch referenced in the vendor's advisory."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/samba", "SMB/NativeLanManager");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if (report_paranoia < 2)
  exit(1, "Report paranoia is low, and this plugin's prone to false positives");

lanman = get_kb_item("SMB/NativeLanManager");
if (isnull(lanman))
  exit(1, "A SMB banner was not found.");

match = eregmatch(string:lanman, pattern:'^Samba ([0-9.]+)$', icase:TRUE);
if (isnull(match))
  exit(1, "The banner does not appear to be Samba.");

version = match[1];
ver_fields = split(version, sep:'.', keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);
rev = int(ver_fields[2]);

# Affected versions:
# 3.3.0 - 3.3.5
# 3.2.0 - 3.2.12
# 3.0.0 - 3.0.34
if (
  major == 3 &&
    ((minor == 3 && rev <= 5) ||
     (minor == 2 && rev <= 12) ||
     (minor == 0 && rev <= 34))
)
{
  port = get_kb_item("SMB/transport");

  if (minor == 3) fix = '3.3.6';
  else if (minor == 2) fix = '3.2.13';
  else if (minor == 0) fix = '3.0.35';

  if (report_verbosity)
  {
    report = string(
      "\n",
      "Installed version : ", version, "\n",
      "Fixed version     : ", fix, "\n"
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);

  exit(0);
}
else exit(1, "Samba version " + version + " is not vulnerable.");

