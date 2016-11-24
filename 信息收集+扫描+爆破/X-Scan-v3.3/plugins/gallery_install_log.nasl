#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(21019);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-4021");
  script_xref(name:"OSVDB", value:"21311");

  script_name(english:"Gallery Install Log Local Information Disclosure");
  script_summary(english:"Checks for Gallery install log");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to an
information disclosure issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Gallery, a web-based photo album
application written in PHP. 

The installation of Gallery on the remote host places its data
directory under the web server's data directory and makes its install
log available to anyone.  Using a simple GET request, a remote
attacker can retrieve this log and discover sensitive information
about the affected application and host, including installation paths,
the admin password hash, etc." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-11/0371.html" );
 script_set_attribute(attribute:"solution", value:
"Move the gallery data directory outside the web server's document root
or remove the file 'install.log' in that directory." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/gallery", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  w = http_send_recv3(method:"GET", item:string(dir, "/g2data/install.log"), port:port);
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # There's a problem if it looks like the install log.
  if ("Prepare installation of the core module" >< res) {
    if (report_verbosity > 1) {
      report = string(
        "\n",
        res
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
