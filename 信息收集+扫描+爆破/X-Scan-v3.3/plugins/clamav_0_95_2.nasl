#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(39437);
  script_version("$Revision: 1.5 $");

  script_bugtraq_id(35398, 35410, 35426);

  script_name(english:"ClamAV < 0.95.2 Multiple Scan Evasion Vulnerabilities");
  script_summary(english:"Checks response to a clamd VERSION command");

  script_set_attribute(attribute:"synopsis", value:
"The remote anti-virus service is vulnerable to a file scan evasion
attack." );
  script_set_attribute(attribute:"description", value:
"According to its version, the clamd anti-virus daemon on the remote
host is earlier than 0.95.2. Such versions are reportedly affected by
multiple scan evasion vulnerabilities :

  - An attacker could bypass anti-virus detection by embedding malicious
    code in a specially crafted 'CAB', 'RAR', or 'ZIP' archive.

  - Due to an issue in 'libclamav/mbox.c', an attacker can bypass anti-
    virus detection by sending a UTF-16 encoded email.

  - Due to an issue in 'libclamav/readdb.c', certain signatures that
    should be rejected are able to bypass detection." );
  script_set_attribute(attribute:"see_also", value:"http://blog.zoller.lu/2009/05/advisory-clamav-generic-bypass.html" );
  script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2009-06/0171.html" );
  script_set_attribute(attribute:"see_also", value:"https://wwws.clamav.net/bugzilla/show_bug.cgi?id=1573" );
  script_set_attribute(attribute:"see_also", value:"https://wwws.clamav.net/bugzilla/show_bug.cgi?id=1615" );
  script_set_attribute(attribute:"see_also", value:"http://svn.clamav.net/svn/clamav-devel/trunk/ChangeLog" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to ClamAV 0.95.2 or later." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("clamav_detect.nasl");
  script_require_keys("Antivirus/ClamAV/version");

  exit(0);
}

include("global_settings.inc");

# nb. banner checks of open-source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) exit(0);

version = get_kb_item("Antivirus/ClamAV/version");
if (!version) exit(0);

port = get_kb_item("Services/clamd");
if (!port) port = 3310;
if (!get_port_state(port)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for (i=0;i<max_index(ver);i++)
  ver[i] = int(ver[i]);

if (
  (
    ver[0] == 0 &&
    (
      ver[1] < 95 ||
      (ver[1] == 95 && ver[2] < 2)
    )
  )
)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Nessus found the following vulnerable version of ClamAV installed on\n",
      "the remote host :",
      "\n",
      "Version: ", version,
      "\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port:port);
}   
