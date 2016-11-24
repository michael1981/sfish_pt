#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42468);
  script_version("$Revision: 1.1 $");

  script_cve_id("CVE-2009-2820");
  script_bugtraq_id(36958);
  script_xref(name:"OSVDB", value:"59854");
  script_xref(name:"Secunia", value:"37308");

  script_name(english:"CUPS < 1.4.2 kerberos Parameter XSS");
  script_summary(english:"Checks CUPS server version");
 
  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote printer service is affected by a cross-site scripting
vulnerability.\n"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"According to its banner, the version of CUPS installed on the remote
host is earlier than 1.4.2.  The 'kerberos' parameter in such versions
is not properly sanitized before being used to generate dynamic HTML
content. 

An attacker can leverage this issue via a combination of attribute
injection and HTTP Parameter Pollution to inject arbitrary script code
into a user's browser to be executed within the security context of
the affected site."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.cups.org/str.php?L3367"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.cups.org/articles.php?L590"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to CUPS version 1.4.2 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
  );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/10/07"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/11/09"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/11/11"
  );
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");
 
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
if (report_paranoia < 2) exit(1,"This plugin only runs if 'Report paranoia' is set to 'Paranoid'.");

if (!get_kb_item("www/cups")) exit(1, "The 'www/cups' KB item is missing.");

port = get_http_port(default:631, embedded: 1);


# Check the version in the banner.
banner = get_http_banner(port:port);
if (!banner) exit(1, "Failed to retrieve the banner from the web server on port "+ port +".");

banner = strstr(banner, "Server:");
banner = banner - strstr(banner, '\r\n');
if ("CUPS/" >< banner)
{
  version = strstr(banner, "CUPS/") - "CUPS/";
  if (version =~ "^1\.([0-3]|4\.[0-1])($|[^0-9])")
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
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
  exit(0,"CUPS version "+ version + " is installed and is not affected.");
}
else exit(0,"The remote banner is not from CUPS.");
