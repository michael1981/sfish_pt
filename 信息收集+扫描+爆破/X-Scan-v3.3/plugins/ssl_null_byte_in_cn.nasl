#
# (C) Tenable Network Security, Inc.
#


# Check if this version of nessusd is too old
if ( NASL_LEVEL < 3208 ) exit(0);


include("compat.inc");

if(description)
{
 script_id(42053);
 script_version ("$Revision: 1.1 $");
 
 script_name(english:"SSL Certificate Null Character Spoofing Weakness");
 script_summary(english:"Determines if the remote SSL/TLS certificate contains a Null");

script_set_attribute(attribute:"synopsis", value:
"This plugin determines if the remote SSL certificate contains a Null 
character." );
 script_set_attribute(attribute:"description", value:
"The remote host contains an SSL certificate with a common name
containing a Null character (\x00) in it.  This may indicate a
compromise or that a program such as SSLsniff is spoofing the
certificate in order to intercept the traffic via a Man-in-The-Middle
(MiTM) attack. 

Certificates with such characters may exploit a bug contained in many
different web browser and other SSL-related products, in how they
validate the common name of such a certificate." );

 script_set_attribute(attribute:"see_also", value:"http://thoughtcrime.org/papers/null-prefix-attacks.pdf" );
 script_set_attribute(attribute:"solution", value:
"Recreate the remote SSL certificate." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C" );

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/06");
 script_end_attributes();

 
 script_category(ACT_GATHER_INFO); 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "General");

 script_dependencie("find_service.nasl");
 script_require_ports("Transport/SSL");
 exit(0);
}

include("global_settings.inc");
include("x509_func.inc");


port = get_kb_item("Transport/SSL");


if ( ! port ) exit(0);

cert = get_server_cert(port:port, encoding:"der");

cert = parse_der_cert(cert:cert);
if (isnull(cert)) exit(0);

report = dump_certificate(cert:cert);
line = strstr(report, "Common Name:");
if ( isnull(line) ) exit(0);
eol  = strstr(line, '\n');
if ( isnull(eol) ) exit(0);
line -= eol;
real_name = str_replace(string:line, find:'\0x00', replace:'.');
eol = strstr(line, '\x00');
fake_name = line - eol;
fake_name -= "Common Name:";

if ( '\x00' >< line ) security_hole(port, extra:'\nThe remote SSL certificate CN was made for :\n\n' + real_name + '\n\nBut it appears to come from :\n\n' + fake_name);
