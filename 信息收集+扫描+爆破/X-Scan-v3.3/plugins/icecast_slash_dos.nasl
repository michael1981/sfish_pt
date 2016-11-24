#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref: gollum <gollum@evilemail.com>
#
#  This script is released under the GNU GPL v2
#
# Changes by Tenable:
# - Revised plugin title, added OSVDB ref, changed family (1/22/2009)


include("compat.inc");

if(description)
{
 script_id(15400);
 script_bugtraq_id(2933);
 script_cve_id("CVE-2001-1083");
 script_xref(name:"OSVDB", value:"5472");
 script_version ("$Revision: 1.7 $");
 
 script_name(english:"Icecast Crafted URI Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote streaming media server is affected by a remote denial of
service vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote server runs a version of Icecast, an open source 
streaming audio server, which is older than version 1.3.11.

This version is affected by a remote denial of service because
Icecast server does not properly sanitize user-supplied input.

An remote attacker could send specially crafted URL, by adding '/', 
'\' or '.' to the end, that may result in a loss of availability for 
the service.

*** Nessus reports this vulnerability using only
*** information that was gathered." );
 script_set_attribute(attribute:"see_also", value:"ftp://ftp.caldera.com/pub/security/OpenLinux/CSSA-2002-020.0.txt" );
 script_set_attribute(attribute:"see_also", value:"http://rhn.redhat.com/errata/RHSA-2002-063.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.debian.org/security/2001/dsa-089" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Icecast 1.3.12 or later, as this reportedly fixes the
issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );


script_end_attributes();

 
 summary["english"] = "Check icecast version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");		
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8000);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:8000);
if(!port) exit(0);

banner = tolower(get_http_banner(port:port));
if ( ! banner ) exit(0);

if("icecast/1." >< banner &&  egrep(pattern:"icecast/1\.(1\.|3\.([0-9]|10)[^0-9])", string:banner))
      security_warning(port);
