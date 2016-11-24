#
# (C) Tenable Network Security, Inc.
#

# Ref: 
# https://www.isc.org/software/bind
# http://cert.uni-stuttgart.de/archive/bugtraq/2003/03/msg00075.html
# 


include("compat.inc");

if(description)
{
 script_id(11318);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2002-0684");
 script_xref(name:"IAVA", value:"2003-B-0001");
 script_xref(name:"OSVDB", value:"14432");

 script_name(english:"ISC BIND < 9.2.2 DNS Resolver Functions Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to use the remote name server to break into the
remote host." );
 script_set_attribute(attribute:"description", value:
"The remote BIND 9 DNS server, according to its version number, is 
vulnerable to a buffer overflow which may allow an attacker to 
gain a shell on this host or to disable this server." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to BIND 9.2.2 or downgrade to the 8.x series" );
 script_set_attribute(attribute:"see_also", value:"https://www.isc.org/software/bind");
 script_set_attribute(attribute:"see_also", value:"http://cert.uni-stuttgart.de/archive/bugtraq/2003/03/msg00075.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.cert.org/advisories/CA-2002-19.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );


 script_end_attributes();
 
 script_summary(english:"Checks the remote BIND version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english: "DNS");
 script_dependencie("bind_version.nasl");
 script_require_keys("bind/version");
 exit(0);
}


vers = get_kb_item("bind/version");
if(!vers)exit(0);

if(ereg(string:vers, pattern:"^9\.[01]\..*"))
{
 security_hole(53);
 exit(0);
}

if(ereg(string:vers, pattern:"^9\.2\.([0-1][^0-9]*|2rc.*)$"))
{
 security_hole(53);
 exit(0);
}
