#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38831);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-1252");
  script_bugtraq_id(35017);
  script_xref(name:"OSVDB", value:"54576");
  script_xref(name:"Secunia", value:"35130");

  script_name(english:"NTP ntpd/ntp_crypto.c crypto_recv() Function Remote Overflow");
  script_summary(english:"Checks the remote ntpd version");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host is running a time server with a remote buffer\n",
      "overflow vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "According to its self-reported version number, the version of ntpd\n",
      "running on the remote host has a stack buffer overflow vulnerability.\n",
      "The vulnerability is in the 'crypto_recv()' function of\n",
      "'ntpd/ntp_crypto.c'. This could allow a remote attacker to crash the\n",
      "service or execute arbitrary code.\n",
      "\n",
      "Note : this issue is only exploitable if ntpd was compiled with\n",
      "OpenSSL support and has autokey authentication enabled. The presence\n",
      "of the following line in ntp.conf indicates a vulnerable system :\n",
      "\n",
      "crypto pw *password*\n",
      "\n",
      "Nessus did not check if the system is configured in this manner."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kb.cert.org/vuls/id/853097"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.ntp.org/bugs/show_bug.cgi?id=1151"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to ntpd version 4.2.4p7 / 4.2.5p74 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("ntp_open.nasl");

  exit(0);
}


include("global_settings.inc");

if (report_paranoia < 2) exit(0);

verbose_ver = get_kb_item("Services/ntp/version");
if (isnull(verbose_ver)) exit(0);

match = eregmatch(string:verbose_ver, pattern:"^ntpd ([^@]+)@");
if (isnull(match)) exit(0);

ver = match[1];
verfields = split(ver, sep:".", keep:FALSE);
major = int(verfields[0]);
minor = int(verfields[1]);
revpatch = split(verfields[2], sep:"p", keep:FALSE);
rev = int(revpatch[0]);
patch = int(revpatch[1]);

# This vulnerability affects NTP 4.x < 4.2.5p74 and < 4.2.4p7
if (
    (major == 4 && minor == 2 && rev == 5 && patch < 74) ||
    (major == 4 && minor == 2 && rev == 4 && patch < 7) ||
    (major == 4 && (minor < 2 || (minor == 2 && rev < 4)))
) security_warning(port:123, proto:"udp");
