#
# (C) Tenable Network Security, Inc.
#
# Starting with Nessus 3.2.1, this script replaces 
# ssl_ciphers.nes
#

# Check if this version of nessusd is too old
if ( NASL_LEVEL < 3208 ) exit(0);


include("compat.inc");

if(description)
{
 script_id(10863);
 script_version ("$Revision: 1.7 $");
 
 script_name(english:"SSL Certificate Information");
 
 script_set_attribute(attribute:"synopsis", value:
"This plugin displays the SSL certificate." );
 script_set_attribute(attribute:"description", value:
"This plugin connects to every SSL-related port and attempts to 
extract and dump the X.509 certificate." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );


script_end_attributes();

 
 summary["english"] = "Displays the server SSL/TLS certificate";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO); 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
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

if (report)
  security_note(port, extra:report);
