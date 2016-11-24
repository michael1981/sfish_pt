#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41056);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(36452);
  script_xref(name:"OSVDB", value:"58206");
  script_xref(name:"Secunia", value:"36716");

  script_name(english:"Interchange < 5.4.4 / 5.6.2 / 5.7.2 Search Request Information Disclosure");
  script_summary(english:"Checks the version of Interchange");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server uses an application server that may be prone to\n",
      "an information disclosure vulnerability."
    )
  );
  
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote host appears to be running Interchange, an open source\n",
      "application server that handles state management, authentication,\n",
      "session maintenance, click trails, filtering, URL encodings, and\n",
      "security policy. \n",
      "\n",
      "According to the banner in its administrative login page, the\n",
      "installed version of Interchange is earlier than 5.4.4 / 5.6.2 /\n",
      "5.7.2.  Such versions are potentially affected by an information\n",
      "disclosure vulnerability.  Any database table configured within\n",
      "Interchange can be queried remotely by an unauthenticated user because\n",
      "the application fails to limit access from its search functions."
    )
  );

  script_set_attribute(
    attribute:"see_also",
    value:"http://ftp.icdevgroup.org/interchange/5.6/ANNOUNCEMENT-5.6.2.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.icdevgroup.org/i/dev/news?mv_arg=00038"
  );

  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Interchange 5.4.4 / 5.6.2 / 5.7.2 or later."
  );

  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
  );

  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/09/17"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/09/23"
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http.inc");
include("misc_func.inc");
include("global_settings.inc");

port = get_http_port(default:80);

#Search for interchange
if (thorough_tests) dirs = list_uniq(make_list("/interchange", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  #Request admin homepage
  url = string(dir, "/admin/login.html");
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(1, "The web server failed to respond.");

  #If it looks like Interchange
  if (
    '<INPUT TYPE=hidden NAME=mv_nextpage VALUE="admin/index">' >< res[2] &&
    egrep(pattern:'^<FORM ACTION=".*/process.*" METHOD=POST name=login>', string:res[2])
  )
  {
    version = egrep(pattern:".*([0-9\.]+) &copy;.*Interchange Development Group&nbsp;", string:res[2]);
    version = version - strstr(version, ' &copy;');
    version = ereg_replace(string:version, pattern:".*([0-9]+\.[0-9]+\.[0-9]+)", replace:"\1");
    if (
      version =~ "^([0-4]\.[0-9\.]+|5\.([0-3]\.[0-9]+|5\.[0-9]+))$" ||
      version =~ "^5\.(4\.[0-3]|6\.[01]|7\.[01])$"
    )
    {
      if (report_verbosity > 0)
      {
        report = string(
          "\n",
          " URL     : ", build_url(port:port, qs:url), "\n",
          " Version : ", version, "\n"
        );
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
      exit(0);
    }
  }
}
