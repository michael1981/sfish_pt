#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  Date: Sun, 13 Apr 2003 18:00:13 +0200
#  From: Jedi/Sector One <j@pureftpd.org>
#  To: bugtraq@securityfocus.com
#  Subject: Multiple vulnerabilities in SheerDNS

include("compat.inc");

if(description)
{
 script_id(11535);
 script_version ("$Revision: 1.11 $");
 script_bugtraq_id(7335, 7336);
 script_xref(name:"OSVDB", value:"32943");
 script_xref(name:"OSVDB", value:"32944");
 
 script_name(english:"SheerDNS < 1.0.1 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to several flaws." );
 script_set_attribute(attribute:"description", value:
"The remote server seems to be running SheerDNS 1.0.0 or older.

This version is vulnerable to several flaws allowing :
	- A remote attacker to read certain files with predefined names
	  (A, PTR, CNAME, ...)

	- A local attacker to read the first line of arbitrary files with the 
	  privileges of the DNS server (typically root)

	- A local attacker to execute arbitrary code through a buffer overflow" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SheerDNS 1.0.1 or disable this service" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );


script_end_attributes();

 script_summary(english:"Determines if the remote DNS server handles malformed names");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"DNS");
 script_dependencies("dns_server.nasl");
 script_require_keys("DNS/udp/53");
 exit(0);
}


function check(str)
{ 
  local_var req, r, soc;

  req = raw_string(0x00, 0x04,
		 0x01, 0x00,
		 0x00, 0x01,
		 0x00, 0x00,
		 0x00, 0x00,
		 0x00, 0x00, 
		strlen(str)) + str +
 	raw_string(0x00, 0x00, 0x01, 0x00, 0x01);

 soc = open_sock_udp(53);
 if (!  soc ) exit(0);
 send(socket:soc, data:req);
 r = recv(socket:soc, length:4096);
 close(soc);

 return r;
}


r = check(str:"localhost");
if(!r)exit(0); # No reply -> quit
if("localhost" >!< r)exit(0); # Does not echo back the query -> quit

r = check(str:"../nessus");
if(!r)exit(0);	# No reply -> good
if("nessus" >< r)exit(0); # Did not modify the name -> good


security_warning(port:53, proto:"udp");
