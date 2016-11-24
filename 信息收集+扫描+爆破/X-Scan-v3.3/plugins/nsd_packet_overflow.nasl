#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38850);
  script_version("$Revision: 1.2 $");

  script_bugtraq_id(35029);
  script_xref(name:"Secunia", value:"35165");

  script_name(english:"NSD packet.c Off-By-One Remote Overflow");
  script_summary(english:"Checks the NSD version number");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The DNS server running on the remote host has a remote buffer\n",
      "overflow vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "According to its self-reported version number, the version of NSD\n",
      "running on the remote host has a stack buffer overflow vulnerability.\n",
      "This could allow a remote attacker to overwrite one byte in memory,\n",
      "leading to a denial of service. It is possible, but unlikely, that\n",
      "this vulnerability could result in remote code execution."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nlnetlabs.nl/publications/NSD_vulnerability_announcement.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "Upgrade to NSD version 3.2.2 or later, or apply the patch referenced\n",
      "in the vendor's advisory."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("nsd_version.nasl");
  script_require_keys("nsd/version");

  exit(0);
}


include("global_settings.inc");

if (report_paranoia < 2) exit(0);

version = get_kb_item("nsd/version");
if (isnull(version)) exit(0);

ver_fields = split(version, sep:".", keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);
rev = int(ver_fields[2]);

# Versions >= 2.0.0 and < 3.2.2 are affected
if (
    major == 2 ||
    (major == 3 && (minor < 2 || (minor == 2 && rev < 2)))
) security_warning(port:53, proto:"udp");

