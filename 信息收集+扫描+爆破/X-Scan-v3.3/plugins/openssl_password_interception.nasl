#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11267);
 script_version("$Revision: 1.31 $");

 script_cve_id("CVE-2003-0078", "CVE-2003-0131", "CVE-2003-0147");
 script_bugtraq_id(6884, 7148);
 script_xref(name:"OSVDB", value:"3945");
 script_xref(name:"OSVDB", value:"3946");
 script_xref(name:"OSVDB", value:"3947");
 script_xref(name:"OSVDB", value:"3948");
 script_xref(name:"RHSA", value:"RHSA-2003:101-01");
 script_xref(name:"SuSE", value:"SUSE-SA:2003:024");
 
 script_name(english:"OpenSSL < 0.9.6j / 0.9.7b Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is using a version
of OpenSSL older than 0.9.6j or 0.9.7b.

This version is vulnerable to a timing based attack which may
allow an attacker to guess the content of fixed data blocks and
may eventually be able to guess the value of the private RSA key
of the server.

An attacker may use this implementation flaw to sniff the
data going to this host and decrypt some parts of it, as well
as impersonate your server and perform man in the middle attacks." );
 script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/secadv_20030219.txt" );
 script_set_attribute(attribute:"see_also", value:"http://lasecwww.epfl.ch/memo_ssl.shtml" );
 script_set_attribute(attribute:"see_also", value:"http://eprint.iacr.org/2003/052/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 0.9.6j (0.9.7b) or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" );


script_end_attributes();

 script_summary(english:"Checks for version of OpenSSL");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 443);
 exit(0);
}

#
# The script code starts here - we rely on Apache to spit OpenSSL's
# version. That sucks.
#

include("http_func.inc");
include("misc_func.inc");
include("backport.inc");

if ( get_kb_item("CVE-2003-0078") ) exit(0);

ports = add_port_in_list(list:get_kb_list("Services/www"), port:443);

foreach port (ports)
{
 banner = get_backport_banner(banner:get_http_banner(port:port));
 if ( ! banner || backported  )  continue;
 if(egrep(pattern:"^Server.*OpenSSL/0\.9\.([0-5][^0-9]|6[^a-z]|6[a-i])", string:banner) || egrep(pattern:"^Server.*OpenSSL/0\.9\.7(-beta|a| )", string:banner)) security_warning(port);
}
