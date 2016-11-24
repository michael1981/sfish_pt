#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(18220);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-1552");
  script_bugtraq_id(13571);

  name["english"] = "GeoHttpServer Unauthorized Image Access Vulnerability";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server does not properly restrict access to files." );
 script_set_attribute(attribute:"description", value:
"The GeoVision Digital Surveillance System installed on the remote host
suffers from a vulnerability that enables anyone to bypass
authentication and view JPEG images stored on the server by calling
them directly." );
 script_set_attribute(attribute:"see_also", value:"http://www.esqo.com/research/advisories/2005/100505-1.txt" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-05/0106.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for unauthorized image access vulnerability in GeoHttpServer";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# Make sure the server both is from GeoVision and tries to authenticate access.
res = http_get_cache(item:"/", port:port);
if (
  res && 
  egrep(string:res, pattern:"^Server: GeoHttpServer") &&
  egrep(string:res, pattern:'<input type="password"')
) {
  # Check for the vulnerability by trying to request up to 16 different images.
  for (i=1; i<=16; i++) {
    w = http_send_recv3(method:"GET", item:string("/cam", i, ".jpg"), port:port);
    if (isnull(w)) exit(1, "the web server did not answer");
    res = w[2];

    # Check whether the result is a JPEG.
    if (
      (res[0] == 0xff && res[1] == 0xd8) ||
      "JFIF" >< res
    ) {
      security_warning(port);
      exit(0);
    }
  }
}
