#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(12515);
 script_version ("$Revision: 1.7 $");

 script_cve_id("CVE-2003-0975");
 script_bugtraq_id(9065);
 script_xref(name:"OSVDB", value:"2860");

 script_name(english:"Mac OS X Safari Null Character Cookie Theft (Security Update 2003-12-05)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X security update." );
 script_set_attribute(attribute:"description", value:
"The remote host is missing Mac OS X Security Update 2003-12-05. This
update fixes a flaw in the Safari web browser that may allow a rogue 
website to access the web cookies of the user of the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f8f9c5b (Jaguar)" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?215c2a0a (Panther)" );
 script_set_attribute(attribute:"solution", value:
"Install security update 2003-12-05." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Check for Security Update 2003-12-05");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");

# Security Update 2004-05-03 actually includes this update for MacOS X 10.2.8 Client
if ( egrep(pattern:"Darwin.* 6\.8\.", string:uname) )
{
 if ( egrep(pattern:"^SecUpd2004-05-03", string:packages) ) exit(0);
}


# MacOS X 10.2.8 and 10.3.1 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.1\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecurityUpd2003-12-05", string:packages) ) security_warning(0);
}
