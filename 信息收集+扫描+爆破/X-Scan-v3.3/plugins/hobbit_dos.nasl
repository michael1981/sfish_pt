#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19307);
  script_version("$Revision: 1.7 $");

  script_bugtraq_id(14365);
  script_xref(name:"OSVDB", value:"18254");

  script_name(english:"Hobbit Monitor < 4.1.0 hobbitd Malformed Message Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server may allow arbitrary code execution." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Hobbit Monitor, an open-source tool for
monitoring servers, applications, and networks. 

The installed version of Hobbit contains a flaw that could lead to the
Hobbit daemon, 'hobbitd', crashing when it tries to process certain
types of messages.  It may also be possible to exploit this flaw in
order to run arbitrary code with the privileges of the hobbit user." );
 script_set_attribute(attribute:"see_also", value:"http://www.hswn.dk/hobbiton/2005/07/msg00242.html" );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?release_id=344499" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Hobbit version 4.1.0 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_summary(english:"Checks for denial of service vulnerability in Hobbit Monitor");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Make sure the affected script exists.
  res = http_get_cache(item:string(dir, "/"), port:port);
  if (res == NULL) exit(0);

  # There's a problem if ...
  if (
    # it looks like Hobbit Monitor and ...
    egrep(string:res, pattern:"<TITLE>.+ : Hobbit - Status @ ") &&
    # the banner indicates it's a version between 4.0 and 4.0.4 inclusive.
    egrep(string:res, pattern:">Hobbit Monitor 4\.0([^.]|\.[0-4]</A>)")
  ) {
    security_hole(port);
    exit(0);
  }
}
