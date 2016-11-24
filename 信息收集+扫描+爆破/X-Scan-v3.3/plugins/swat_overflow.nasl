#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(13660);
  script_version ("$Revision: 1.8 $");
  script_cve_id("CVE-2004-0600");
  script_bugtraq_id(10780);
  script_xref(name:"OSVDB", value:"8190");

  script_name(english:"Samba SWAT HTTP Basic Auth base64 Overflow");
  script_summary(english:"SWAT overflow");

   script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to a buffer overflow.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote host is running SWAT - a web-based administration tool for
Samba.

There is a buffer overflow condition in the remote version of this software
which might allow an attacker to execute arbitrary code on the remote host
by sending a malformed authorization request (or any malformed base64 data).'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Upgrade to Samba 3.0.5 or later.'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/bugtraq/2004-07/0249.html'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/bugtraq/2004-07/0256.html'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/bugtraq/2004-07/0258.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK); # Or ACT_ATTACK ? Swat is started from inetd after all...
  script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");
  script_dependencie("swat_detect.nasl");
  script_require_ports("Services/swat", 901);
  script_require_keys("Settings/ParanoidReport");
  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/swat");
if(!port) port = 901;

if (! get_port_state(port)) exit(0);

w = http_send_recv3(method: "GET", port: port, item: "/", username: "", password: "",
  add_headers: make_array("Authorization", "Basic aaa="));
if (isnull(w)) exit(1, "the web server did not answer");

res = strcat(w[0], w[1], '\r\n', w[2]);
if ('realm="SWAT"' >!< res ) exit(0);

w = http_send_recv3(method:"GET", port: port, item: "/", username: "", password: "",
  add_headers: make_array("Authorization", "Basic ="));

if (isnull(w)) security_hole(port);
