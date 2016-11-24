#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
 script_id(10590);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2000-0938");
 script_xref(name:"OSVDB", value:"487");

 script_name(english:"Samba Web Administration Tool (SWAT) Error Message Username Enumeration");
 script_summary(english:"Detect SWAT server port");
   script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to information disclosure.'
  );

  script_set_attribute(
    attribute:'description',
    value:'he remote SWAT server replies with different error codes when
it is issued a bad user name or a bad password.

An attacker may use this flaw to obtain the list of
user names of the remote host by a brute force attack.

As SWAT does not log login attempts, an attacker may use
this flaw even more effectively/'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Upgrade to the latest Samba packages.'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/bugtraq/2000-10/0430.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N'
  );

  script_end_attributes();
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("swat_detect.nasl");
  script_require_ports("Services/swat");
  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_kb_item("Services/swat");
if(!port) exit(0);

if (! get_port_state(port)) exit(0);

 soctcp901 = http_open_socket(port);

 if (soctcp901)
 {
  #
  # First attempt - we try to log in as nosuchuser1234:nopass
  #
  w = http_send_recv3(method:"GET", item:"/", port:port,
    username: "nosuchuser1234", password: "nopass");
  if (isnull(w)) exit(1, "the web server did not answer");
  code1 = w[0];

  #
  # Second attempt - we try to log in as root:nopass
  #
  w = http_send_recv3(method:"GET", item:"/", port:port,
    username: "root", password: "nopass");
  if (isnull(w)) exit(1, "the web server did not answer");
  code2 = w[0];

  if(("401" >< code1)  &&
     ("401" >< code2))
     {
       if(code1 != code2)security_warning(port);
      }
 }
