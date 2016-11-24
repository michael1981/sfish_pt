# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# GPL
#
# Ref: Juan Pablo Martinez Kuhn

# Changes by Tenable:
# - Changed plugin family (6/16/09)


include("compat.inc");

if(description)
{
 script_id(14314);
 script_version ("$Revision: 1.11 $");

 script_cve_id("CVE-2004-1701", "CVE-2004-1702");
 script_bugtraq_id(10899, 10900);
 script_xref(name:"OSVDB", value:"8406");
 script_xref(name:"OSVDB", value:"14664");

 script_name(english:"Cfengine AuthenticationDialogue() Function Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability.
Cfengine is running on this remote host.");

 script_set_attribute(attribute:"description", value:
"Cfengine cfservd is reported prone to a remote heap-based buffer
overrun vulnerability. 

The vulnerability presents itself in the cfengine cfservd
AuthenticationDialogue() function.  The issue exists due to a lack of
sufficient boundary checks performed on challenge data that is
received from a client. 

In addition, cfengine cfservd is reported prone to a remote denial of
service vulnerability.  The vulnerability presents itself in the
cfengine cfservd AuthenticationDialogue() function which is
responsible for processing SAUTH commands and also performing RSA
based authentication.  The vulnerability presents itself because
return values for several statements within the
AuthenticationDialogue() function are not checked." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-02/0333.html" );
 script_set_attribute(attribute:"see_also", value:"http://security.gentoo.org/glsa/glsa-200408-08.xml" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to 2.1.8 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 script_summary(english:"check for cfengine flaw based on its version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"Gain a shell remotely");
 script_require_ports(5308);

 script_dependencies("cfengine_detect.nasl");
 exit(0);
}

port = 5308;
if ( ! get_kb_item("cfengine/running") ) exit(0);
version = get_kb_item("cfengine/version");
if (version)
{
 if (egrep(pattern:"^2\.(0\.|1\.[0-7]([^0-9]|$))", string:version))
  security_warning(port);
}
