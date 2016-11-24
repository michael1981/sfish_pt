#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36183);
  script_version("$Revision: 1.10 $");

  script_cve_id(
    "CVE-2008-5286", 
    "CVE-2009-0163", 
    "CVE-2009-0164",
    "CVE-2009-0195",
    "CVE-2009-0949"
  );
  script_bugtraq_id(32518, 34571, 34665, 34791, 35169);
  script_xref(name:"OSVDB", value:"50494");
  script_xref(name:"OSVDB", value:"54461");
  script_xref(name:"OSVDB", value:"54462");
  script_xref(name:"OSVDB", value:"54490");
  script_xref(name:"OSVDB", value:"55002");
  script_xref(name:"Secunia", value:"34481");

  script_name(english:"CUPS < 1.3.10 Multiple Vulnerabilities");
  script_summary(english:"Checks CUPS server version");
 
  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote printer service is affected by multiple vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "According to its banner, the version of CUPS installed on the remote\n",
      "host is earlier than 1.3.10.  Such versions are affected by several\n",
      "issues :\n",
      "\n",
      "  - A potential integer overflow in the PNG image validation\n",
      "    code in '_cupsImageReadPNG()' could allow an attacker to\n",
      "    crash the affected service or possibly execute arbitrary\n",
      "    code. (STR #2974)\n",
      "\n",
      "  - A heap-based integer overflow exists in\n",
      "    '_cupsImageReadTIFF()' due to a failure to properly\n",
      "    validate the image height of a specially crafted TIFF\n",
      "    file, which can be leveraged to execute arbitrary code.\n",
      "    (STR #3031)\n",
      "\n",
      "  - The web interface may be vulnerable to DNS rebinding\n",
      "    attacks due to a failure to validate the HTTP Host\n",
      "    header in incoming requests. (STR #3118)\n",
      "\n",
      "  - A heap-based buffer overflow in pdftops allows remote\n",
      "    attackers to execute arbitrary code via a PDF file with \n",
      "    crafted JBIG2 symbol dictionary segments. (CVE-2009-0195)",
      "\n",
      "  - Flawed 'ip' structure initialization in the function",
      "    'ippReadIO()' could allow an anonymous remote attacker",
      "    to crash the application via a malicious IPP request ",
      "    packet with two consecutives IPP_TAG_UNSUPPORTED tags.",
      "    (CVE-2009-0949)"
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.cups.org/str.php?L2974"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.cups.org/str.php?L3031"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.cups.org/str.php?L3118"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://secunia.com/secunia_research/2009-18/"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.coresecurity.com/content/AppleCUPS-null-pointer-vulnerability"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/504032/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.cups.org/articles.php?L582"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to CUPS version 1.3.10 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
 
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/cups");
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
if (!get_port_state(port)) exit(0);


# Check the version in the banner.
banner = get_http_banner(port:port);
if (!banner) exit(0);

banner = strstr(banner, "Server:");
banner = banner - strstr(banner, '\r\n');
if ("CUPS/" >< banner)
{
  version = strstr(banner, "CUPS/") - "CUPS/";
  if (version =~ "^1\.([0-2]|3\.[0-9])($|[^0-9])")
  {
    if (report_verbosity > 0)
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
