#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(20746);
 script_version("$Revision: 1.13 $");

 script_cve_id("CVE-2006-0306", "CVE-2006-0307");
 script_bugtraq_id(16276);
 script_xref(name:"OSVDB", value:"22529");

 script_name(english:"CA DM Deployment Common Component Multiple DoS");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to cause a denial of service against the remote
service." );
 script_set_attribute(attribute:"description", value:
"The remote version of DMPrimer service (CA DM Deployment 
Common Component) is vulnerable to multiple Denial
of Service attacks.
An attacker can crash or may cause a high CPU utilization by
sending a specially crafted UDP packets." );
 script_set_attribute(attribute:"see_also", value:"http://supportconnectw.ca.com/public/ca_common_docs/dmdeploysecurity_notice.asp" );
 script_set_attribute(attribute:"solution", value:
"Disable the DMPrimer service." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 script_summary(english:"Determines the version of the remote DMPrimer service");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("dmprimer_detect.nasl");
 script_require_keys("CA/DMPrimer");
 script_require_ports(5727);
 exit(0);
}

#

version = get_kb_item ("CA/DMPrimer");

if (!isnull (version) &&
    ( (version == "1.4.154") || (version == "1.4.155") ) )
  security_warning(5727);
