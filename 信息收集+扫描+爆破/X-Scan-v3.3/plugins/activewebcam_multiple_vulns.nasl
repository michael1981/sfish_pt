#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(17320);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-0730", "CVE-2005-0731", "CVE-2005-0732", "CVE-2005-0733", "CVE-2005-0734");
  script_bugtraq_id(12778);
  script_xref(name:"OSVDB", value:"14638");
  script_xref(name:"OSVDB", value:"14639");
  script_xref(name:"OSVDB", value:"14640");
  script_xref(name:"OSVDB", value:"14641");
  script_xref(name:"OSVDB", value:"14642");

  script_name(english:"Active WebCam Webserver <= 5.5 Multiple Vulnerabilities (DoS, Path Disc)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of PY Software's Active WebCam webserver running on the
remote host is prone to multiple vulnerabilities:

  o Denial of Service Vulnerabilities.
    A request for a file on floppy drive may result in a dialog
    prompt, causing service to cease until it is acknowledged by an
    administrator. In addition, requesting the file 'Filelist.html'
    reportedly causes CPU usage on the remote host to increase,
    ultimately leading to denial of service.

  o Information Disclosure Vulnerabilities.
    A request for a nonexistent file will return an error message
    with the installation path for the software. Further, error
    messages differ depending on whether a file exists or is
    inaccessible. An attacker may exploit these issues to gain
    information about the filesystem on the remote host.

Note that while versions 4.3 and 5.5 are known to be affected, earlier
versions are likely to be as well." );
 script_set_attribute(attribute:"see_also", value:"http://secway.org/advisory/ad20050104.txt" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-03/0216.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple remote vulnerabilities in Active WebCam webserver 5.5 and older";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8080);


# Grab the main page and make sure it's for Active WebCam.
res = http_get_cache(item:"/", port:port);
if ('name="GENERATOR" content="Active WebCam' >!< res) exit(0);

if (safe_checks()) {
  if (egrep(string:res, pattern:'name="GENERATOR" content="Active WebCam ([0-4][^0-9]|5\\.[0-5] )'))
    security_warning(port);
}
else {
  # Let's request a nonexistent page and see if we can find the install path.
  # Use the number of microseconds in the time for the page.
  now = split(gettimeofday(), sep:".", keep:0);
  page = now[1];

  r = http_send_recv3(method:"GET", item:"/" + page, port:port);
  res = strcat(r[0], r[1], '\r\n', r[2]);

  pat = "The requested file: <B>([^<]+)</B> was not found.";
  matches = egrep(string:res, pattern:pat, icase:TRUE);
  foreach match (split(matches)) {
    match = chomp(match);
    path = eregmatch(pattern:pat, string:match);
    if (!isnull(path)) {
      path = path[1];
      if (ereg(string:path, pattern:"^[A-Za-z]:\\")) security_warning(port);
    }
  }
}
