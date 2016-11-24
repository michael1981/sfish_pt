#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33577);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2008-1722");
  script_bugtraq_id(28781);
  script_xref(name:"OSVDB", value:"44398");
  script_xref(name:"Secunia", value:"29809");

  script_name(english:"CUPS < 1.3.8 PNG File Handling Multiple Overflows");
  script_summary(english:"Checks CUPS server version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote printer service (CUPS) is affected by a buffer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of CUPS installed on the remote
host is affected by an integer overflow.  Using a specially crafted
PNG file with overly long width and height fields, a remote attacker
can leverage this issue to crash the affected service and may allow
execution of arbitrary code." );
 script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L2790" );
 script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/218395" );
 script_set_attribute(attribute:"see_also", value:"http://www.cups.org/articles.php?L562" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CUPS version 1.3.8 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
 
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

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
  if (version =~ "^1\.([0-2]|3\.[0-7])($|[^0-9])")
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "CUPS version ", version, " appears to be running on the remote host based\n",
        "on the following Server response header :\n",
        "\n",
        "  ", banner, "\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
}
