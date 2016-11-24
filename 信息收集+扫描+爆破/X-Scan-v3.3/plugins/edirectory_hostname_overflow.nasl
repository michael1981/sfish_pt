#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22903);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2006-5478");
  script_bugtraq_id(20655);
  script_xref(name:"OSVDB", value:"29993");
  script_xref(name:"Secunia", value:"22519");

  script_name(english:"Novell eDirectory iMonitor HTTP Protocol Stack (httpstk) Host HTTP Header Remote Overflow");
  script_summary(english:"Send a special Host request header to eDirectory");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server is affected by a buffer overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The installed version of Novell eDirectory on the remote host\n",
      "reportedly contains a buffer overflow that can be triggered with a\n",
      "specially-crafted Host request header.  An anonymous remote attacker\n",
      "may be able to leverage this flaw to execute code on the affected\n",
      "host, generally with super-user privileges."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mnin.org/advisories/2006_novell_httpstk.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.neohapsis.com/archives/fulldisclosure/2006-10/0434.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/filefinder/security/index.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Apply the eDirectory Post 8.7.3.8 FTF1 / 8.8.1 FTF1 patch as\n",
      "appropriate."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8028);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


function make_request (data, port)
{
 local_var line, req;

 # Send a special query.
 req = "";
 foreach line (split(http_get(item:"/nds", port:port)))
 {
  if ("Host: " >< line) 
    line = ereg_replace(
      pattern : "Host: .+", 
      replace : string("Host: ", data, "\r\n"),
      string  : line
    );
  req += line;
 }

 return req;
}



port = get_http_port(default:8028);


# Make sure the server looks like eDirectory.
banner = get_http_banner (port:port);
if (!egrep(pattern:"Server: .*HttpStk/[0-9]+\.[0-9]+", string:banner)) exit(0);


# Get the format of a normal host location

req = make_request (data:"nessus", port:port);
r = http_send_recv_buf(port:port, data:req);
if (isnull(r)) exit(0);
res = strcat(r[0], r[1], '\r\n', r[2]);

res = egrep(pattern:string("^Location: https?://nessus:[0-9]+/nds"), string:res);
if (res == NULL)
  exit (0);

# Create a special host location string

http = ereg_replace (pattern:"^Location: (https?://)nessus:[0-9]+/nds.*", string:res, replace:"\1");
sport = ereg_replace (pattern:"^Location: https?://nessus:([0-9]+)/nds.*", string:res, replace:"\1");

magic = crap(data:"A", length:62 - strlen(http) - strlen(sport));
req = make_request(data:magic, port:port);

r = http_send_recv_buf(port:port, data:req);
if (isnull(r)) exit(0);

res = egrep(pattern:string("^Location: https?://", magic, ":[0-9]+/nds"), string:res);
if (res == NULL)
  exit (0);
res = strcat(r[0], r[1], '\r\n', r[2]);

s = ereg_replace (pattern:"^Location: (https?://A+:[0-9]+/nds).*", string:res, replace:"\1");

# Patched version should skip 1 character in the port number
if (strlen(s) == 67)
  security_hole(port);
