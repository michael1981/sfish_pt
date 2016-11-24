#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(22257);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2006-4370", "CVE-2006-4371");
  script_bugtraq_id(19620, 19631);
  script_xref(name:"OSVDB", value:"28122");
  script_xref(name:"OSVDB", value:"28123");

  script_name(english:"WebAdmin < 3.2.5 Multiple Vulnerabilities");
  script_summary(english:"Checks version of WebAdmin");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running WebAdmin, a web-based remote administration
tool for Alt-N MDaemon. 

According to its banner, the installed version of WebAdmin fails to
properly filter directory traversal sequences from the 'file'
parameter of the 'logfile_view.wdm' and 'configfile_view.wdm' scripts. 
A global administrator can leverage this issue to read and write to
arbitrary files on the affected host, subject to the privileges of the
web server user id, which in the case WebAdmin's internal web server
is used, is LOCAL SYSTEM. 

In addition, the affected application also reportedly allows a domain
administrator to edit the account of a global administrator, which can
be leveraged to login as the global administrator by changing his
password." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2006-08/0586.html" );
 script_set_attribute(attribute:"see_also", value:"http://lists.altn.com/WebX?50@813.igqdaKNhCRb.0@.eeb9cff" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WebAdmin 3.2.5 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 1000);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:1000);

# Get the version number from the initial page.
res = http_get_cache(item:"/", port:port);
if (res == NULL) exit(0);

# There's a problem if ...
if (
  # it looks like WebAdmin and ...
  '<title>WebAdmin</title>' >< res &&
  '<form name="waForm" action="login.wdm"' >< res &&
  # it's version < 3.2.5
  egrep(pattern:">WebAdmin</A> v([0-2]\..*|3\.([01]\..*|2\.[0-4])) &copy;", string:res)
) security_hole(port);
