#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# This script is released under the GNU GPLv2


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(14611);
 script_version ("$Revision: 1.17 $");
 script_name(english:"AIX Maintenance Level");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote operating system is not up to date." );
 script_set_attribute(attribute:"description", value:
"The remote AIX system is lagging behind its official maintenance level
and is therefore missing critical security patches." );
 script_set_attribute(attribute:"see_also", value:"http://www-912.ibm.com/eserver/support/fixes/" );
 script_set_attribute(attribute:"solution", value:
"Update the remote AIX server to the newest maintenance level." );
 script_set_attribute(attribute:"risk_factor", value:"High" );
 script_end_attributes();

 
 summary["english"] = "Check for maintenance level patch"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 
 family["english"] = "AIX Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/AIX/oslevel");
 exit(0);
}


#the code

#here the list of last maintenance level
level4330=11;
level5100=9;
level5200=10;
level5300=8;

buf=get_kb_item("Host/AIX/oslevel");
if (!buf) exit(0);

 v=split(buf, sep:"-",keep: 0);
 if (isnull(v)) exit(0);
 osversion=int(v[0]);
 level=int(chomp(v[1]));

if (osversion==4330 && level < level4330)
{
str="The remote host is missing an AIX maintenance package.
Maintenance level "+level+" is installed, last is "+level4330;
 security_hole(port:0, extra: str);
  exit(0);
}

if (osversion==5100 && level < level5100)
{
str="The remote host is missing an AIX maintenance package.
Maintenance level "+level+" is installed, last is "+level5100;

 security_hole(port:0, extra: str);
  exit(0);
}

if (osversion==5200 && level < level5200)
{
str="The remote host is missing an AIX maintenance package.
Maintenance level "+level+" is installed, last is "+level5200;

 security_hole(port:0, extra: str);
  exit(0);
}

if (osversion==5300 && level < level5300)
{
str="The remote host is missing an AIX maintenance package.
Maintenance level "+level+" is installed, last is "+level5300;

 security_hole(port:0, extra: str);
  exit(0);
}
