#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(27608);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-4351");
  script_bugtraq_id(26268);
  script_xref(name:"OSVDB", value:"42028");

  script_name(english:"CUPS cups/ipp.c ippReadIO Function IPP Tag Handling Overflow");
  script_summary(english:"Checks CUPS server version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote printer service is prone to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of CUPS installed on the remote
host fails to check the text-length field in the 'ippReadIO()'
function in 'cups/ipp.c'.  Using a specially-crafted request with an
IPP (Internet Printing Protocol) tag such as 'textWithLanguage' or
'nameWithLanguage' and an overly large text-length value, a remote
attacker may be able to leverage this issue to execute arbitrary code
on the affected system." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2007-76/advisory/" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/483033/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L2561" );
 script_set_attribute(attribute:"see_also", value:"http://www.cups.org/articles.php?L508" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CUPS version 1.3.4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
 
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/cups", "Settings/ParanoidReport");
  script_require_ports("Services/www",631);

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
  if (version =~ "^(0\.|1\.([0-2]\.|3\.[0-3]($|[^0-9])))")
  {
    report = string(
      "The remote CUPS server returned the following banner :\n",
      "\n",
      "  ", banner, "\n"
    );
    security_hole(port:port, extra:report);
  }
}
