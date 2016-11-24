#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31730);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2008-0047", "CVE-2008-1373");
  script_bugtraq_id(28307, 28544);
  script_xref(name:"OSVDB", value:"43376");
  script_xref(name:"OSVDB", value:"44160");
  script_xref(name:"OSVDB", value:"48699");

  script_name(english:"CUPS < 1.3.7 Multiple Vulnerabilities (Overflow, Info Disc)");
  script_summary(english:"Checks CUPS server version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote printer service is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of CUPS installed on the remote
host is affected by several issues :

  - A buffer overflow in 'cgiCompileSearch' that can lead
    to arbitrary code execution (STR #2729).

  - A GIF image filter overflow involving 'code_size' 
    value from a user-supplied GIF image used in 
    'gif_read_lzw' (STR #2765).

  - A temporary file with Samba credentials may be left 
    behind by cupsaddsmb if no Windows drivers were
    installed (STR #2779)." );
 script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L2729" );
 script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L2765" );
 script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L2779" );
 script_set_attribute(attribute:"see_also", value:"http://www.cups.org/articles.php?L537" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CUPS version 1.3.7 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P" );
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
  if (version =~ "^1\.([0-2]|3\.[0-6])($|[^0-9])")
  {
    if (report_verbosity)
    {
      report = string(
        "The remote CUPS server returned the following banner :\n",
        "\n",
        "  ", banner, "\n"
      );
      security_note(port:port, extra:report);
    }
    else security_note(port);
  }
}
