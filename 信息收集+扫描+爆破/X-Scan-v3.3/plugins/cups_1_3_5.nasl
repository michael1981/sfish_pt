#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(29727);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2007-5849");
  script_bugtraq_id(26917);
  script_xref(name:"OSVDB", value:"40719");

  script_name(english:"CUPS SNMP Back End (backend/snmp.c) asn1_get_string Function Crafted SNMP Response Remote Overflow");
  script_summary(english:"Checks CUPS server version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote printer service is affected by a buffer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of CUPS installed on the remote
host contains a stack-based integer overflow in 'asn1_get_string' in
'backend/snmp.c'.  Provided the SNMP backend is configured in CUPS
(true by default in CUPS 1.2 but not 1.3), an attacker may be able to
leverage this issue using specially-crafted SNMP responses with
negative lengths to overflow a buffer and execute arbitrary code on
the affected system." );
 script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L2589" );
 script_set_attribute(attribute:"see_also", value:"http://www.cups.org/articles.php?L519" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CUPS version 1.3.5 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
 
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/cups", "Settings/ParanoidReport");
  script_require_ports("Services/www", 631);
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


# nb: banner checks of open-source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) exit(0);


if (!get_kb_item("www/cups")) exit(0);


port = get_http_port(default:631, embedded: 1);

# Check the version in the banner.
banner = get_http_banner(port:port);
if (!banner) exit(0);

banner = strstr(banner, "Server:");
banner = banner - strstr(banner, '\r\n');
if ("CUPS/" >< banner)
{
  version = strstr(banner, "CUPS/") - "CUPS/";
  # nb: STR #2589 says 1.1 is not affected.
  if (version =~ "^1\.(2|3\.[0-4])($|[^0-9])")
  {
    report = string(
      "The remote CUPS server returned the following banner :\n",
      "\n",
      "  ", banner, "\n"
    );
    security_hole(port:port, extra:report);
  }
}
