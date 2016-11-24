#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31131);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2008-0882");
  script_bugtraq_id(27906);
  script_xref(name:"OSVDB", value:"42030");
  script_xref(name:"Secunia", value:"28994");

  script_name(english:"CUPS < 1.3.6 process_browse_data() Function Double Free DoS");
  script_summary(english:"Checks CUPS server version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote printer service is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of CUPS installed on the remote
host contains a double free error in its 'process_browse_data'
function when deleting the mime type entry for a remote printer that
is being polled.  An attacker may be able to leverage this issue to
crash the affected service by deleting a printer under his control and
then recreating it as a class. 

Third-party researchers suggest this vulnerability can be used to
execute arbitrary code." );
 script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L2656" );
 script_set_attribute(attribute:"see_also", value:"http://www.cups.org/articles.php?L529" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CUPS version 1.3.6 or later." );
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
  if (version =~ "^1\.([0-2]|3\.[0-5])($|[^0-9])")
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
