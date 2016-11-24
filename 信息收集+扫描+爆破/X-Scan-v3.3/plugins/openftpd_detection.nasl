#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14179);
 script_version("$Revision: 1.7 $");
 script_cve_id("CVE-2004-2523");
 script_bugtraq_id(10830);
 script_xref(name:"OSVDB", value:"8261");

 script_name(english:"OpenFTPD SITE MSG FTP Command Format String");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server may be vulnerable to a format string attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running OpenFTPD - an FTP server designed to help
file sharing (aka 'warez').  Some version of this server are
vulnerable to a remote format string attack which may allow an
authenticated attacker to execute arbitrary code on the remote host. 

Note that Nessus did not actually check for this flaw, so this might
be a false positive." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-08/0017.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-07/0350.html" );
 script_set_attribute(attribute:"solution", value:
"Disable the remote service." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P" );
script_end_attributes();

 
 script_summary(english:"Determines the presence of OpenFTPD");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencies("find_service2.nasl");
 script_require_ports(21, "Services/ftp");
 exit(0);
}


include("ftp_func.inc");
port = get_kb_item("Services/ftp");
if ( ! port ) port = 21;
if ( ! get_port_state(port) ) exit(0);
banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);

#
# We only check for the banner :
# - Most (all) OpenFTPD server do not accept anonymous connections
# - The use of OpenFTPD is not encouraged in a corporation environment
#
if ( egrep(pattern:"^220 OpenFTPD server", string:banner ) )
	security_warning(port);
