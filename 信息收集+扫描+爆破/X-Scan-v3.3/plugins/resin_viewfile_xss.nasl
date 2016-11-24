#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33273);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-2462");
  script_bugtraq_id(29948);
  script_xref(name:"OSVDB", value:"46515");
  script_xref(name:"Secunia", value:"30845");

  script_name(english:"Resin viewfile Servlet file Parameter XSS");
  script_summary(english:"Tries to inject script code through viewfile error");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java Servlet that is affected by a
cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Resin, an application server. 

The 'viewfile' Servlet included with the version of Resin installed on
the remote host fails to sanitize user input to the 'file' parameter
before including it in dynamic HTML output.  An attacker may be able
to leverage this issue to inject arbitrary HTML and script code into a
user's browser to be executed within the security context of the
affected site. 

Note that the affected Servlet is part of the Resin documentation,
which should not be installed on production servers." );
 script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/305208" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ea1b70f" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Resin or Resin Pro version 3.1.4 / 3.0.25 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:8080);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


exploit = string("nessus<script>alert('", SCRIPT_NAME, "')</script>");

test_cgi_xss(port: port, ctrl_re: "Resin/", cgi: "/viewfile",
  dirs: make_list("/resin-doc"), qs: "file="+urlencode(str:exploit),
  pass_str: "<b>File not found /"+exploit );

