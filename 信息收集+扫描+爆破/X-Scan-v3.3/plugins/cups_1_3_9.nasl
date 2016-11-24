#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34385);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2008-3639", "CVE-2008-3640", "CVE-2008-3641");
  script_bugtraq_id(31688, 31690);
  script_xref(name:"OSVDB", value:"49130");
  script_xref(name:"OSVDB", value:"49131");
  script_xref(name:"OSVDB", value:"49132");
  script_xref(name:"Secunia", value:"32226");

  script_name(english:"CUPS < 1.3.9 Multiple Vulnerabilities");
  script_summary(english:"Checks CUPS server version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote printer service is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of CUPS installed on the remote
host is earlier than 1.3.9.  Such versions are affected by several
issues :

  - The HP-GL/2 filter does not adequately check the ranges
    on the pen width and pen color opcodes, which allows an 
    attacker to overwrite memory addresses with arbitrary
    data and which may result in execution of arbitrary code
    (STR #2911).

  - There is a heap-based buffer overflow in the SGI file
    format parsing module that can be triggered with
    malformed Run Length Encoded (RLE) data to execute 
    arbitrary code (STR #2918).

  - There is an integer overflow vulnerability in the
    'WriteProlog()' function in the 'texttops'
    application that can be triggered when calculating
    the page size used for storing PostScript data to
    execute arbitrary code (STR #2919)." );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-067/" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-10/0175.html" );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=752" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-11/0014.html" );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=753" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-11/0015.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L2911" );
 script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L2918" );
 script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L2919" );
 script_set_attribute(attribute:"see_also", value:"http://www.cups.org/articles.php?L575" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CUPS version 1.3.9 or later." );
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
  if (version =~ "^1\.([0-2]|3\.[0-8])($|[^0-9])")
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
