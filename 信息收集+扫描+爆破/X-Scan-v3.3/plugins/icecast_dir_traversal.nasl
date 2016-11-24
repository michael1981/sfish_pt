#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref: gollum <gollum@evilemail.com>
#
#  This script is released under the GNU GPL v2
#
# Changes by Tenable:
# - Revised plugin title, changed family (1/22/2009)


include("compat.inc");

if(description)
{
 script_id(15396);
 script_bugtraq_id(2932);
 script_cve_id("CVE-2001-0784");
 script_xref(name:"OSVDB", value:"1883");
 script_version ("$Revision: 1.6 $");
 
 script_name(english:"Icecast Encoded Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote streaming audio server is affected by an information
disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote server runs a version of Icecast, an open source 
streaming audio server, which is version 1.3.10 or older.

These versions are affected by a directory traversal flaw because the
application fails to properly sanitize user supplied input.

An attacker could send specially crafted URL to view arbitrary files 
on the system.

*** Nessus reports this vulnerability using only
*** information that was gathered." );
 script_set_attribute(attribute:"see_also", value:"ftp://ftp.caldera.com/pub/security/OpenLinux/CSSA-2002-020.0.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.debian.org/security/2001/dsa-089" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2001-06/0353.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Icecast 1.3.12 or later as this reportedly fixes the issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );


script_end_attributes();

 
 summary["english"] = "Check icecast version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
		
 script_family(english:"CGI abuses");
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
if (! banner ) exit(0);

if("icecast/" >< banner && 
   egrep(pattern:"icecast/1\.([012]\.|3\.[0-9][^0-9])", string:banner))
      security_warning(port);
