#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(25662);
 script_version("$Revision: 1.6 $");
 script_cve_id("CVE-2006-5855");
 script_bugtraq_id(21440);
 script_xref(name:"OSVDB", value:"31764");
 script_xref(name:"OSVDB", value:"31765");
 script_xref(name:"OSVDB", value:"31766");

 script_name(english:"IBM Tivoli Storage Manager Multiple Remote Overflows");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of IBM Tivoli Storage Manager
which is vulnerable to multiple buffer overflows.  An attacker may
exploit these flaws to execute arbitrary code on the remote host or to
disable this service remotely. 

To exploit this flaw, an attacker would need to send a specially
crafted packet to the remote service." );
 script_set_attribute(attribute:"see_also", value:"http://dvlabs.tippingpoint.com/advisory/TPTI-06-14" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to :

- Tivoli Storage Manager >= 5.2.9
- Tivoli Storage Manager >= 5.3.4
- Tivoli Storage Manager Express >= 5.3.7.1" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 script_summary(english:"Test the IBM TSM buffer overflows");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_require_keys("IBM/TSM/Version");
 script_dependencies("ibm_tsm_detect.nasl");
 script_require_ports(1500);
 exit(0);
}


version = get_kb_item("IBM/TSM/Version");
isExpress = get_kb_item("IBM/TSM/isExpress");

if (isnull(version))
  exit(0);

port = 1500;

v = split(version, sep:".", keep:FALSE);

if (!isExpress)
{
 if ( ( int(v[0]) < 5 ) ||
      ( int(v[0]) == 5 && int(v[1]) < 2 ) ||
      ( int(v[0]) == 5 && int(v[1]) == 2 && int(v[2]) < 9 ) ||
      ( int(v[0]) == 5 && int(v[1]) == 3 && int(v[2]) < 4 ) )
  security_hole(port);
}
else
{
 if ( ( int(v[0]) < 5 ) ||
      ( int(v[0]) == 5 && int(v[1]) < 3 ) ||
      ( int(v[0]) == 5 && int(v[1]) == 3 && int(v[2]) < 7 ) ||
      ( int(v[0]) == 5 && int(v[1]) == 3 && int(v[2]) == 7 && int(v[3]) < 1 ) )
   security_hole(port); 
}
